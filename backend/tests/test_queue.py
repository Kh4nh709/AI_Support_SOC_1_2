"""DB tests for app.tier1.queue — `list_queue`, `risk_band`, `latest_suggestion`,
`get_alert_view` (P4-T02).

Fixtures go through `domain.transitions.open_alert` → `start_enrichment` →
`finish_enrichment` from the canonical `alert_40112.json` and edited copies
(`dataclasses.replace`); the non-`status` columns a test needs (`risk_score`,
`first_seen_at`, `occurrence_count`, `triaged_count`, `triage_status`,
`is_synthetic`) are set with a direct `UPDATE` — none of them is `status` (G2).
`llm_runs` rows are inserted directly in **P3-T10's shape** (planning decision 5):
`llm_runs` is empty on every host until P3-T10 lands, so every suggestion test
here brings its own row. Every test runs inside the `db` fixture's transaction
and is rolled back (conftest.py). `TEST_DATABASE_URL=postgresql:///soc_p4t02_test`.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import (
    acknowledge,
    decide,
    finish_enrichment,
    open_alert,
    start_enrichment,
)
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.kb.lookup import get_playbook
from app.tier1 import queue, visibility
from app.tier1.queue import (
    PAGE_SIZE_DEFAULT,
    PAGE_SIZE_MAX,
    RETRIAGE_ABS_DELTA,
    RETRIAGE_FACTOR,
    QueuePage,
    Suggestion,
    get_alert_view,
    latest_suggestion,
    latest_suggestions,
    list_queue,
    risk_band,
)
from app.tier1.visibility import ANALYST_HIDE, LABELING_DENYLIST, LABELING_PREFIXES

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CANONICAL: Alert = parse_wazuh_alert(
    json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))
).alert
assert _CANONICAL is not None
_T = _CANONICAL.alert_time  # 2026-08-16 17:56:56 UTC

USER_ID = "00000000-0000-0000-0000-000000040200"
USER_NAME = "P4-T02 analyst"

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={},
)

# P3-T10's proposer row, quoted from the card (design note 6).
RESULT: dict[str, Any] = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "structured_basis": {
        "severity": "critical",
        "ioc_reputation": "skipped",
        "asset_criticality": "unknown",
        "identity_privileged": "unknown",
        "occurrence_count": 1,
        "playbook_rule_applied": None,
    },
    "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    "playbook_used": None,
}
GATE: dict[str, Any] = {
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "forced": False,
    "forced_by": [],  # a LIST — security/gate.py:42,90 appends step names to a list (DEC-101)
    "warnings": [],
    "facts": {"correlated_clusters": 2},
    "verifier_verdict": "false_positive",
}
VERIFIER_RESULT: dict[str, Any] = {
    "agree": True,
    "structured_only_verdict": "false_positive",
    "reason": "r",
}

_counter = itertools.count()


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _alert(**overrides: Any) -> Alert:
    """The canonical alert with a fresh `alert_id` and whatever else the test edits."""
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"p4t02-{n}")
    fields: dict[str, Any] = {"alert_id": alert_id, "event_bucket_hash": _hash(alert_id)}
    fields.update(overrides)
    return dataclasses.replace(_CANONICAL, **fields)


def _set(conn: psycopg.Connection, alert_id: str, **columns: Any) -> None:
    """Direct UPDATE of non-`status` columns (`risk_score`, `first_seen_at`, ...)."""
    assert "status" not in columns
    assignments = ", ".join(f"{column} = %s" for column in columns)
    conn.execute(
        f"UPDATE alerts SET {assignments} WHERE alert_id = %s", (*columns.values(), alert_id)
    )


def _queued(
    conn: psycopg.Connection,
    *,
    risk_score: int | None = 50,
    suggestion_visible: bool = True,
    source: str = "wazuh",
    **overrides: Any,
) -> str:
    """A `queued_tier1` head through the real transitions. `risk_score=None`
    leaves the column NULL (an alert whose enrichment never finished)."""
    alert = _alert(**overrides)
    open_alert(conn, alert, kind="received", source=source, suggestion_visible=suggestion_visible)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(
        conn,
        alert.alert_id,
        context=_EMPTY_CONTEXT,
        risk_score=risk_score if risk_score is not None else 0,
        risk_components={},
    )
    if risk_score is None:
        _set(conn, alert.alert_id, risk_score=None)
    return alert.alert_id


def _duplicate(conn: psycopg.Connection, head_id: str, **overrides: Any) -> str:
    alert = _alert(**overrides)
    open_alert(
        conn, alert, kind="duplicate", source="wazuh", suggestion_visible=True, duplicate_of=head_id
    )
    return alert.alert_id


def _seed_user(conn: psycopg.Connection) -> None:
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, 'p4t02-analyst', %s, 'tier1', 'x') ON CONFLICT (user_id) DO NOTHING",
        (USER_ID, USER_NAME),
    )


def _insert_run(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    role: str = "proposer",
    result: dict | None = RESULT,
    gate_result: dict | None = GATE,
    stopped_by: str | None = None,
    offset_s: int = 0,
) -> str:
    """One `llm_runs` row in P3-T10's shape. `offset_s` orders rows inside one
    transaction, where `now()` is the same for every statement."""
    row = conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result, stopped_by, created_at) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, %s, %s::jsonb, "
        "%s, now() + %s * interval '1 second') RETURNING run_id",
        (
            alert_id,
            json.dumps(result) if result is not None else None,
            role,
            json.dumps(gate_result) if gate_result is not None else None,
            stopped_by,
            offset_s,
        ),
    ).fetchone()
    return str(row[0])


def _all_rows(conn: psycopg.Connection, **kwargs: Any) -> list[dict]:
    """Every queue row, paging through with the maximum page size (`kwargs` are `list_queue`'s:
    the sort, P10-T14)."""
    rows: list[dict] = []
    page = 1
    while True:
        result = list_queue(conn, page=page, page_size=PAGE_SIZE_MAX, **kwargs)
        rows.extend(result.rows)
        if len(rows) >= result.total or not result.rows:
            return rows
        page += 1


def _row(conn: psycopg.Connection, alert_id: str) -> dict:
    matches = [row for row in _all_rows(conn) if row["alert_id"] == alert_id]
    assert len(matches) == 1, f"{alert_id} appears {len(matches)} times in the queue"
    return matches[0]


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_keys(item)


def _walk_string_values(value: Any, *, skip_keys: frozenset[str]):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in skip_keys:
                continue
            for path, leaf in _walk_string_values(item, skip_keys=skip_keys):
                yield (f"{key}.{path}" if path else key), leaf
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            for path, leaf in _walk_string_values(item, skip_keys=skip_keys):
                yield (f"[{i}].{path}" if path else f"[{i}]"), leaf
    elif isinstance(value, str):
        yield "", value


# ---------------------------------------------------------------------------
# Pure: the band and the constants
# ---------------------------------------------------------------------------


def test_risk_band_edges_and_clamp():
    assert risk_band(None) is None
    assert risk_band(0) == "Thấp"
    assert risk_band(24) == "Thấp"
    assert risk_band(25) == "Vừa"
    assert risk_band(49) == "Vừa"
    assert risk_band(50) == "Cao"
    assert risk_band(74) == "Cao"
    assert risk_band(75) == "Rất cao"
    assert risk_band(100) == "Rất cao"
    # Outside 0–100 is clamped (phase-4 constraint 3 caps the formula at 100).
    assert risk_band(101) == "Rất cao"
    assert risk_band(-1) == "Thấp"


def test_retriage_constants_are_v1_and_paging_limits():
    assert RETRIAGE_FACTOR == 10
    assert RETRIAGE_ABS_DELTA == 200
    assert PAGE_SIZE_DEFAULT == 50
    assert PAGE_SIZE_MAX == 200


# ---------------------------------------------------------------------------
# list_queue
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_queue_order_needs_retriage_then_risk_desc_nulls_last_then_first_seen_asc(db):
    ratio = _queued(db, risk_score=50)
    _set(db, ratio, occurrence_count=100, triaged_count=5)  # 100 >= 5 * 10 → retriage
    delta = _queued(db, risk_score=10)
    _set(db, delta, occurrence_count=250, triaged_count=40)  # 250 - 40 >= 200 → retriage
    early = _queued(db, risk_score=90)
    _set(db, early, first_seen_at=datetime.now(UTC) - timedelta(hours=1))
    late = _queued(db, risk_score=90)  # first_seen_at = now(): after `early`
    quiet = _queued(db, risk_score=60)
    _set(db, quiet, occurrence_count=30, triaged_count=5)  # neither branch
    never_triaged = _queued(db, risk_score=40)
    _set(db, never_triaged, occurrence_count=999, triaged_count=0)  # triaged_count = 0 guard
    zero = _queued(db, risk_score=0)
    null = _queued(db, risk_score=None)
    mine = {ratio, delta, early, late, quiet, never_triaged, zero, null}

    rows = [row for row in _all_rows(db) if row["alert_id"] in mine]

    assert [row["alert_id"] for row in rows] == [
        ratio,
        delta,
        early,
        late,
        quiet,
        never_triaged,
        zero,
        null,
    ]
    assert [row["needs_retriage"] for row in rows] == [True, True] + [False] * 6
    assert rows[-1]["risk_band"] is None  # NULLS LAST: the un-enriched head sinks
    assert rows[0]["risk_band"] == "Cao"


def _retriage_head(conn: psycopg.Connection, *, risk_score: int, suggestion_visible: bool) -> str:
    """A head ① has triaged once (`triaged_count` 1) that has since grown to 12 occurrences:
    12 >= 1 * RETRIAGE_FACTOR, so the queue would flag it `needs_retriage`."""
    alert_id = _queued(conn, risk_score=risk_score, suggestion_visible=suggestion_visible)
    _set(conn, alert_id, triaged_count=1, occurrence_count=12)
    return alert_id


def _order(conn: psycopg.Connection, *alert_ids: str, **kwargs: Any) -> list[dict]:
    """The queue rows for `alert_ids`, in queue order (`kwargs`: `list_queue`'s sort)."""
    return [row for row in _all_rows(conn, **kwargs) if row["alert_id"] in set(alert_ids)]


@pytest.mark.db
def test_queue_blind_retriage_head_has_neither_key_and_does_not_jump_the_queue(db):
    """R17 / DEC-101: ① is the only first-time writer of `triaged_count`, so on a blind head a
    `needs_retriage` that flips on — or a row that moves to the top — says "① ran". Neither key
    reaches the analyst and the flag does not order the row: risk decides, as for any head."""
    blind = _retriage_head(db, risk_score=5, suggestion_visible=False)
    higher_risk = _queued(db, risk_score=90, suggestion_visible=False)

    rows = _order(db, blind, higher_risk)

    assert [row["alert_id"] for row in rows] == [higher_risk, blind]
    for row in rows:
        assert "triaged_count" not in row and "needs_retriage" not in row


@pytest.mark.db
def test_queue_visible_retriage_head_keeps_both_keys_and_sorts_first(db):
    visible = _retriage_head(db, risk_score=5, suggestion_visible=True)
    higher_risk = _queued(db, risk_score=90, suggestion_visible=True)

    rows = _order(db, visible, higher_risk)

    assert [row["alert_id"] for row in rows] == [visible, higher_risk]
    assert rows[0]["needs_retriage"] is True and rows[0]["triaged_count"] == 1
    assert rows[1]["needs_retriage"] is False and rows[1]["triaged_count"] == 0


@pytest.mark.db
def test_queue_blind_and_visible_retriage_heads_mixed(db):
    """The visible arm's ⟳ rows lead; a blind ⟳ row falls among the rest by risk."""
    visible = _retriage_head(db, risk_score=1, suggestion_visible=True)
    top = _queued(db, risk_score=90, suggestion_visible=False)
    blind = _retriage_head(db, risk_score=60, suggestion_visible=False)
    low = _queued(db, risk_score=20, suggestion_visible=True)

    rows = _order(db, visible, top, blind, low)

    assert [row["alert_id"] for row in rows] == [visible, top, blind, low]
    assert [("needs_retriage" in row) for row in rows] == [True, False, False, True]


@pytest.mark.db
def test_queue_sort_and_strip_share_one_notion_of_decided(db, monkeypatch):
    """The SQL sort key and `visibility.strip` must agree on what a decided head is: both read
    `visibility.SHOW_STATES` when the query runs, so widening it re-opens the keys and the
    ⟳ ordering together (a literal list copied into the SQL would drift from `strip`)."""
    blind = _retriage_head(db, risk_score=5, suggestion_visible=False)
    higher_risk = _queued(db, risk_score=90, suggestion_visible=False)
    assert [row["alert_id"] for row in _order(db, blind, higher_risk)] == [higher_risk, blind]

    monkeypatch.setattr(visibility, "SHOW_STATES", visibility.SHOW_STATES | {"queued_tier1"})
    rows = _order(db, blind, higher_risk)

    assert [row["alert_id"] for row in rows] == [blind, higher_risk]
    assert rows[0]["needs_retriage"] is True and rows[0]["triaged_count"] == 1


@pytest.mark.db
def test_queue_unavailable_alert_still_listed(db):
    """H6 / phase-6: `LEFT JOIN`, not `JOIN` — an alert ① could not process is
    exactly the one that must not disappear from the queue."""
    alert_id = _queued(db, suggestion_visible=True)
    _set(db, alert_id, triage_status="unavailable")

    row = _row(db, alert_id)

    assert row["triage_status"] == "unavailable"
    assert row["run_id"] is None
    assert row["suggested_action"] is None
    assert row["confidence"] is None
    assert row["gate_forced"] is None
    assert row["proposed_action"] is None and row["held_by"] == []  # P14-T03


@pytest.mark.db
def test_queue_row_has_band_not_score(db):
    high = _queued(db, risk_score=80, suggestion_visible=True)
    none = _queued(db, risk_score=None, suggestion_visible=True)

    row = _row(db, high)

    assert "risk_score" not in row
    assert row["risk_band"] == "Rất cao"
    assert _row(db, none)["risk_band"] is None
    assert set(row) == {
        "alert_id",
        "rule_id",
        "description",
        "category",
        "severity",
        "agent_name",
        "alert_user",  # P10-T15 / DEC-165: not derived from ①, so it is not `ANALYST_HIDE`
        "srcip",
        "occurrence_count",
        "triaged_count",
        "first_seen_at",
        "last_seen_at",
        "alert_time",
        "suggestion_visible",
        "triage_status",
        "status",
        "run_id",
        "suggested_action",
        "confidence",
        "gate_forced",
        "proposed_action",  # P14-T03 / DEC-213: the model's own answer, an `ANALYST_HIDE` key
        "held_by",  # P14-T03 / DEC-213: why the system held it, an `ANALYST_HIDE` key
        "needs_retriage",
        "risk_band",
    }
    assert row["status"] == "queued_tier1"
    assert row["severity"] == "critical"
    assert isinstance(row["first_seen_at"], datetime)  # a datetime, not a string (rule 11)


@pytest.mark.db
def test_queue_blind_row_has_no_suggestion_keys(db):
    alert_id = _queued(db, suggestion_visible=False)
    _insert_run(db, alert_id)

    row = _row(db, alert_id)

    for key in ANALYST_HIDE:
        assert key not in row, key
    assert "run_id" not in row  # a blind row does not even say "① ran" (DEC-101)
    assert "triage_status" not in row
    assert row["suggestion_visible"] is False  # the analyst may know they are on the blind arm
    # R17 / DEC-101: the counts say how often ① ran, so a blind row hides them too.
    assert "triaged_count" not in row and "needs_retriage" not in row
    assert row["occurrence_count"] == 1  # the cluster size itself is not ① metadata
    assert row["alert_id"] == alert_id


@pytest.mark.db
def test_queue_visible_row_has_suggestion(db):
    alert_id = _queued(db, suggestion_visible=True)
    run_id = _insert_run(db, alert_id)

    row = _row(db, alert_id)

    assert row["suggested_action"] == "false_positive"
    assert row["confidence"] == "high"
    assert row["gate_forced"] is False
    assert row["run_id"] == run_id
    assert row["triage_status"] == "pending"  # the test never ran ① — the column is untouched


@pytest.mark.db
@pytest.mark.parametrize("suggestion_visible", [True, False], ids=["visible", "blind"])
def test_queue_row_carries_alert_user_and_srcip_on_both_arms(db, suggestion_visible):
    """P10-T15 / DEC-165: with every alert its own row, identical alerts are told apart by the
    user and the source address. Neither is derived from ① (both come from the alert as
    received), so a blind row carries them exactly as a visible one does (DEC-101, R17)."""
    alert_id = _queued(
        db, suggestion_visible=suggestion_visible, alert_user="alice", srcip="203.0.113.9"
    )
    _insert_run(db, alert_id)

    row = _row(db, alert_id)

    assert row["alert_user"] == "alice"
    assert row["srcip"] == "203.0.113.9"
    if not suggestion_visible:  # and the ① keys stay gone, so the new keys leak nothing new
        for key in ANALYST_HIDE:
            assert key not in row, key
    assert "alert_user" not in ANALYST_HIDE and "srcip" not in ANALYST_HIDE


@pytest.mark.db
def test_queue_row_alert_user_may_be_null_and_srcip_empty(db):
    """`alert_user` is nullable and `srcip` is `TEXT NOT NULL DEFAULT ''` (B1/D10): the API
    passes both through as stored — the page shows "—" for either."""
    alert_id = _queued(db, alert_user=None, srcip="")

    row = _row(db, alert_id)

    assert row["alert_user"] is None
    assert row["srcip"] == ""


@pytest.mark.db
def test_queue_order_total_and_bands_ignore_the_two_new_columns(db):
    """The two new columns are read-only display: the order is still risk desc, then arrival;
    `total` and `counts_by_band` count the same rows. Users and addresses are chosen so that
    sorting on either would reverse the risk order."""
    before = list_queue(db, page_size=PAGE_SIZE_MAX)
    low = _queued(db, risk_score=10, alert_user="aaa", srcip="1.1.1.1")
    mid = _queued(db, risk_score=50, alert_user="mmm", srcip="5.5.5.5")
    high = _queued(db, risk_score=90, alert_user="zzz", srcip="9.9.9.9")

    page = list_queue(db, page_size=PAGE_SIZE_MAX)
    ours = [row["alert_id"] for row in page.rows if row["alert_id"] in {low, mid, high}]

    assert ours == [high, mid, low]
    assert page.total == before.total + 3
    assert sum(page.counts_by_band.values()) == sum(before.counts_by_band.values()) + 3


@pytest.mark.db
def test_queue_lateral_join_picks_proposer_and_does_not_double(db):
    """① writes a proposer *and* a verifier row per alert; the phase-6 plain
    `LEFT JOIN` would return the head twice. The LATERAL join picks the latest
    proposer row and only that."""
    baseline = list_queue(db).total
    alert_id = _queued(db, suggestion_visible=True)
    proposer = _insert_run(db, alert_id, role="proposer")
    _insert_run(
        db,
        alert_id,
        role="verifier",
        result=VERIFIER_RESULT,
        gate_result={
            "role": "verifier",
            "compared_to": "false_positive",
            "proposer_run_id": proposer,
        },
        offset_s=1,
    )

    rows = [row for row in _all_rows(db) if row["alert_id"] == alert_id]
    assert len(rows) == 1
    assert rows[0]["run_id"] == proposer
    assert rows[0]["suggested_action"] == "false_positive"
    assert list_queue(db).total == baseline + 1

    # A later proposer row (a re-triage) is the one that shows; still one row.
    later = _insert_run(
        db,
        alert_id,
        role="proposer",
        result={**RESULT, "suggested_action": "true_positive"},
        offset_s=2,
    )
    rows = [row for row in _all_rows(db) if row["alert_id"] == alert_id]
    assert len(rows) == 1
    assert rows[0]["run_id"] == later
    assert rows[0]["suggested_action"] == "true_positive"

    # DEC-217: a still later run stored as `needs_review` (version 1: the old gate held it) is served as the
    # model's own `proposed_verdict`, which `GATE` says is `false_positive`
    latest = _insert_run(
        db,
        alert_id,
        role="proposer",
        result={**RESULT, "suggested_action": "needs_review"},
        offset_s=4,
    )
    rows = [row for row in _all_rows(db) if row["alert_id"] == alert_id]
    assert len(rows) == 1
    assert rows[0]["run_id"] == latest
    assert rows[0]["suggested_action"] == "false_positive"


@pytest.mark.db
def test_queue_excludes_synthetic_and_non_queued(db):
    _seed_user(db)
    queued = _queued(db)
    synthetic = _queued(db)
    _set(db, synthetic, is_synthetic=True)
    active = _queued(db)
    acknowledge(db, active, USER_ID)  # queued_tier1 → tier1_active
    received = _alert()
    open_alert(db, received, kind="received", source="wazuh", suggestion_visible=True)
    head = _queued(db)
    duplicate = _duplicate(db, head)

    listed = {row["alert_id"] for row in _all_rows(db)}

    assert queued in listed
    assert head in listed
    assert not ({synthetic, active, received.alert_id, duplicate} & listed)


@pytest.mark.db
def test_queue_pagination_offset_and_total(db):
    baseline = list_queue(db).total
    mine = [_queued(db, risk_score=100 - i) for i in range(5)]

    first = list_queue(db, page=1, page_size=2)
    assert isinstance(first, QueuePage)
    assert first.total == baseline + 5
    assert first.page == 1 and first.page_size == 2
    assert len(first.rows) == 2

    pages = [first]
    page = 2
    while len([row for p in pages for row in p.rows]) < first.total:
        pages.append(list_queue(db, page=page, page_size=2))
        page += 1
    seen = [row["alert_id"] for p in pages for row in p.rows]
    assert len(seen) == first.total == len(set(seen))  # no row twice, none missed
    assert [alert_id for alert_id in seen if alert_id in set(mine)] == mine  # risk desc, stable
    assert all(p.total == first.total for p in pages)
    beyond = list_queue(db, page=page, page_size=2)
    assert beyond.rows == [] and beyond.total == first.total


@pytest.mark.db
def test_queue_page_size_clamped_and_invalid_rejected(db):
    with pytest.raises(ValueError):
        list_queue(db, page=0)
    with pytest.raises(ValueError):
        list_queue(db, page=-1)
    with pytest.raises(ValueError):
        list_queue(db, page_size=0)
    assert list_queue(db, page_size=PAGE_SIZE_MAX + 1).page_size == PAGE_SIZE_MAX
    assert list_queue(db, page_size=10_000).page_size == PAGE_SIZE_MAX
    assert list_queue(db).page_size == PAGE_SIZE_DEFAULT
    assert list_queue(db, page_size=7).page_size == 7


# ---------------------------------------------------------------------------
# list_queue — the sort (P10-T14, DEC-164)
# ---------------------------------------------------------------------------


def _sort_head(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    agent: str = "alpha",
    last_seen_h: int = 1,
    occ: int = 1,
    risk: int | None = 50,
    first_seen_min: int = 0,
    triaged: int = 0,
    visible: bool = True,
) -> str:
    """A queued head with every sort column set explicitly (hours/minutes after `_T`).
    `last_seen_at` must not precede `first_seen_at` (`ck_alerts_last_seen_khong_lui`): keep
    `last_seen_h * 60 >= first_seen_min`."""
    _queued(conn, alert_id=alert_id, risk_score=risk, agent_name=agent, suggestion_visible=visible)
    _set(
        conn,
        alert_id,
        last_seen_at=_T + timedelta(hours=last_seen_h),
        occurrence_count=occ,
        first_seen_at=_T + timedelta(minutes=first_seen_min),
        triaged_count=triaged,
    )
    return alert_id


#: name: (agent, last_seen h, occurrences, risk, first_seen min). Every key has ties on purpose:
#: n3/n4/n5/n6 share `last_seen`; n2/n4, n5/n6 and n1/n3 share `occurrences`; n5/n6 tie on
#: everything but the agent, so only the final `alert_id` tie-breaker orders them under `time`
#: and `occurrences`.
_SORT_SEED = {
    "n1": ("alpha", 5, 3, 10, 5),
    "n2": ("bravo", 1, 30, 90, 4),
    "n3": ("charlie", 3, 3, 50, 3),
    "n4": ("charlie", 3, 30, 80, 2),
    "n5": ("alpha", 3, 12, 50, 1),
    "n6": ("bravo", 3, 12, 50, 1),
}


def _seed_sortable(conn: psycopg.Connection) -> dict[str, str]:
    """`_SORT_SEED` inserted in an order unlike any expected one (n6 first), so a missing final
    tie-breaker shows as arrival order. Returns name -> alert_id."""
    ids: dict[str, str] = {}
    for name in ("n6", "n2", "n4", "n1", "n5", "n3"):
        agent, last_seen_h, occ, risk, first_seen_min = _SORT_SEED[name]
        ids[name] = _sort_head(
            conn,
            f"p10t14-{name}",
            agent=agent,
            last_seen_h=last_seen_h,
            occ=occ,
            risk=risk,
            first_seen_min=first_seen_min,
        )
    return ids


# (sort, dir, expected order). A tie on the sort key falls to risk DESC, first_seen ASC, alert_id
# ASC — in that direction whatever `dir` is (n3/n4/n5/n6 keep n4, n5, n6, n3 both ways).
_SORT_CASES = [
    ("time", None, ["n1", "n4", "n5", "n6", "n3", "n2"]),
    ("time", "desc", ["n1", "n4", "n5", "n6", "n3", "n2"]),
    ("time", "asc", ["n2", "n4", "n5", "n6", "n3", "n1"]),
    ("occurrences", None, ["n2", "n4", "n5", "n6", "n3", "n1"]),
    ("occurrences", "desc", ["n2", "n4", "n5", "n6", "n3", "n1"]),
    ("occurrences", "asc", ["n3", "n1", "n5", "n6", "n2", "n4"]),
    ("agent", None, ["n5", "n1", "n2", "n6", "n4", "n3"]),
    ("agent", "asc", ["n5", "n1", "n2", "n6", "n4", "n3"]),
    ("agent", "desc", ["n4", "n3", "n2", "n6", "n5", "n1"]),
]


@pytest.mark.db
@pytest.mark.parametrize(("sort", "direction", "expected"), _SORT_CASES)
def test_queue_sort_orders_each_key_in_both_directions(db, sort, direction, expected):
    ids = _seed_sortable(db)

    rows = _order(db, *ids.values(), sort=sort, direction=direction)

    assert [row["alert_id"] for row in rows] == [ids[name] for name in expected]


@pytest.mark.db
def test_queue_sort_ties_break_by_risk_then_first_seen_then_id_and_paging_is_stable(db):
    """Nine heads equal on every column but the id, inserted in descending id order: whatever
    the key, the only thing that can order them is `alert_id ASC`, and page 1 + 2 + 3 must be
    that same order with no head twice or missing (OFFSET paging over a total order)."""
    ids = [f"p10t14-tie{i}" for i in range(9)]
    for alert_id in reversed(ids):
        _sort_head(db, alert_id, agent="alpha", last_seen_h=2, occ=7, risk=40, first_seen_min=1)

    for sort, direction in (("time", None), ("occurrences", "asc"), ("agent", "desc")):
        pages = [
            list_queue(db, page=n, page_size=4, sort=sort, direction=direction) for n in (1, 2, 3)
        ]
        listed = [row["alert_id"] for p in pages for row in p.rows]
        assert [alert_id for alert_id in listed if alert_id in set(ids)] == ids, (sort, direction)
        assert len(listed) == len(set(listed)), (sort, direction)  # no head on two pages
        assert len(pages[0].rows) == len(pages[1].rows) == 4
        assert pages[0].total == pages[1].total == pages[2].total


@pytest.mark.db
def test_queue_sort_risk_is_the_default_and_takes_no_direction(db):
    """`sort` omitted, `sort="risk"` and today's call return the same order, and it is today's:
    `needs_retriage` first (visible heads only), then risk DESC NULLS LAST, then first_seen ASC."""
    retriage = _sort_head(db, "p10t14-r1", risk=5, occ=12, triaged=1)
    high = _sort_head(db, "p10t14-r2", risk=90, first_seen_min=2)
    high_later = _sort_head(db, "p10t14-r3", risk=90, first_seen_min=3)
    low = _sort_head(db, "p10t14-r4", risk=20)
    unscored = _sort_head(db, "p10t14-r5", risk=None)
    mine = (retriage, high, high_later, low, unscored)

    expected = [retriage, high, high_later, low, unscored]
    assert [r["alert_id"] for r in _order(db, *mine)] == expected
    assert [r["alert_id"] for r in _order(db, *mine, sort="risk")] == expected
    assert [r["alert_id"] for r in _order(db, *mine, sort="risk", direction=None)] == expected


@pytest.mark.db
def test_queue_sort_risk_blind_retriage_head_still_does_not_jump(db):
    """R17 under the explicit `sort="risk"` and the omitted one: a blind head ① has triaged once
    (`triaged_count` 1) that grew to 12 occurrences stays where its risk puts it."""
    blind = _sort_head(db, "p10t14-b1", risk=5, occ=12, triaged=1, visible=False)
    higher_risk = _sort_head(db, "p10t14-b2", risk=90, visible=False)

    for kwargs in ({}, {"sort": "risk"}):
        assert [r["alert_id"] for r in _order(db, blind, higher_risk, **kwargs)] == [
            higher_risk,
            blind,
        ], kwargs


@pytest.mark.db
@pytest.mark.parametrize("sort", ["time", "occurrences", "agent"])
def test_queue_sort_blind_head_does_not_move_when_triaged_count_changes(db, sort):
    """DEC-101/R17: ① is the only first-time writer of `triaged_count`. On a blind head, ① running
    (`triaged_count` 0 → 1, which makes 12 occurrences `needs_retriage`) must not change its
    position under any key. x sits in the middle of every default order."""
    top = _sort_head(db, "p10t14-y", agent="alpha", last_seen_h=3, occ=50, visible=False)
    x = _sort_head(db, "p10t14-x", agent="bravo", last_seen_h=2, occ=12, visible=False)
    bottom = _sort_head(db, "p10t14-z", agent="charlie", last_seen_h=1, occ=5, visible=False)

    def positions() -> list[str]:
        return [r["alert_id"] for r in _order(db, top, x, bottom, sort=sort)]

    assert positions() == [top, x, bottom]
    for triaged in (1, 2, 12):
        _set(db, x, triaged_count=triaged)
        assert positions() == [top, x, bottom], (sort, triaged)


@pytest.mark.db
@pytest.mark.parametrize("sort", ["time", "occurrences", "agent"])
def test_queue_sort_needs_retriage_plays_no_part_even_on_the_visible_arm(db, sort):
    """`needs_retriage` leads the risk order only. Under another key a visible ⟳ head sorts where
    the key puts it, not first."""
    top = _sort_head(db, "p10t14-vy", agent="alpha", last_seen_h=3, occ=50)
    x = _sort_head(db, "p10t14-vx", agent="bravo", last_seen_h=2, occ=12, triaged=1)
    bottom = _sort_head(db, "p10t14-vz", agent="charlie", last_seen_h=1, occ=5)

    rows = _order(db, top, x, bottom, sort=sort)

    assert [r["alert_id"] for r in rows] == [top, x, bottom]
    assert rows[1]["needs_retriage"] is True  # the flag is still shown; it just does not order


@pytest.mark.db
def test_queue_sort_leaves_total_and_counts_by_band_alone(db):
    _sort_head(db, "p10t14-c1", risk=90, occ=3)
    _sort_head(db, "p10t14-c2", risk=60, occ=9)
    _sort_head(db, "p10t14-c3", risk=10, occ=1)

    plain = list_queue(db, page_size=2)
    for sort, direction in (("time", None), ("occurrences", "asc"), ("agent", "desc")):
        sorted_page = list_queue(db, page_size=2, sort=sort, direction=direction)
        assert sorted_page.total == plain.total
        assert sorted_page.counts_by_band == plain.counts_by_band
        assert (sorted_page.page, sorted_page.page_size) == (plain.page, plain.page_size)
        assert len(sorted_page.rows) == len(plain.rows)


@pytest.mark.db
def test_queue_sort_composes_with_the_filters(db):
    high_new = _sort_head(db, "p10t14-f1", risk=80, last_seen_h=4)
    high_old = _sort_head(db, "p10t14-f2", risk=80, last_seen_h=1)
    low = _sort_head(db, "p10t14-f3", risk=5, last_seen_h=9)

    page = list_queue(db, band="critical", sort="time", direction="asc")

    assert [r["alert_id"] for r in page.rows if r["alert_id"] in {high_new, high_old}] == [
        high_old,
        high_new,
    ]
    assert low not in [r["alert_id"] for r in page.rows]


@pytest.mark.db
@pytest.mark.parametrize(
    ("sort", "direction"),
    [
        ("bogus", None),
        ("", None),
        ("Time", None),
        ("time ", None),
        ("risk; DROP TABLE alerts; --", None),
        ("time", "sideways"),
        ("time", ""),
        ("time", "ASC"),
        ("occurrences", "asc; --"),
        ("risk", "asc"),
        ("risk", "desc"),
        ("risk", ""),
    ],
)
def test_queue_sort_refuses_an_unknown_value_or_a_direction_on_risk(db, sort, direction):
    with pytest.raises(ValueError, match="sort|dir"):
        list_queue(db, sort=sort, direction=direction)
    assert list_queue(db).total >= 0  # the table is still there and the connection usable


# --- the whitelist (no database) --------------------------------------------------------------


def test_queue_sort_whitelist_keys_are_exactly_the_four_and_none_reads_the_suggestion():
    """DEC-164 / DEC-101: the sort keys are `{risk, time, occurrences, agent}` and nothing else.
    A field ① writes or derives (`triaged_count`, `needs_retriage`, `triage_status`, the
    suggestion, its confidence, the gate) is never a key, so a row's position never says ①
    ran. `risk` is the one order that carries `needs_retriage`, and only through the
    visible-or-decided guard (`_NEEDS_RETRIAGE_SORT_SQL`)."""
    table = queue.QUEUE_ORDER_BY
    assert {sort for sort, _direction in table} == {"risk", "time", "occurrences", "agent"}
    assert set(table) == {
        ("risk", None),
        ("time", "asc"),
        ("time", "desc"),
        ("occurrences", "asc"),
        ("occurrences", "desc"),
        ("agent", "asc"),
        ("agent", "desc"),
    }

    assert table[("risk", None)] == (
        f"{queue._NEEDS_RETRIAGE_SORT_SQL} DESC, a.risk_score DESC NULLS LAST, a.first_seen_at ASC"
    )
    allowed = {
        "last_seen_at",
        "occurrence_count",
        "agent_name",
        "risk_score",
        "first_seen_at",
        "alert_id",
    }
    for (sort, direction), fragment in table.items():
        if sort == "risk":
            continue
        columns = set(re.findall(r"\ba\.(\w+)", fragment))
        assert columns <= allowed, (sort, direction, columns)
        assert "%(" not in fragment and "{" not in fragment, (sort, direction)
        assert not re.search(r"\br\.|llm_runs|triage|suggest|confidence|gate", fragment)
        assert fragment.endswith(
            "a.risk_score DESC NULLS LAST, a.first_seen_at ASC, a.alert_id ASC"
        )


def test_queue_sort_defaults_and_fragments_match_the_contract():
    assert queue.SORT_DEFAULT_DIR == {"time": "desc", "occurrences": "desc", "agent": "asc"}
    table = queue.QUEUE_ORDER_BY
    assert table[("time", "desc")].startswith("a.last_seen_at DESC NULLS LAST, ")
    assert table[("time", "asc")].startswith("a.last_seen_at ASC NULLS LAST, ")
    assert table[("occurrences", "desc")].startswith("a.occurrence_count DESC, ")
    assert table[("occurrences", "asc")].startswith("a.occurrence_count ASC, ")
    assert table[("agent", "asc")].startswith("a.agent_name ASC NULLS LAST, ")
    assert table[("agent", "desc")].startswith("a.agent_name DESC NULLS LAST, ")


# ---------------------------------------------------------------------------
# latest_suggestion — the one reader of ① (planning decision 5)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_latest_suggestion_none_when_result_null(db):
    alert_id = _queued(db)
    assert latest_suggestion(db, alert_id) is None  # no row at all

    _insert_run(db, alert_id, result=None, gate_result={"error": "schema"}, stopped_by="schema")
    assert latest_suggestion(db, alert_id) is None  # ① failed: `stopped_by` set, result NULL

    # A verifier row alone is not a suggestion either.
    other = _queued(db)
    _insert_run(
        db, other, role="verifier", result=VERIFIER_RESULT, gate_result={"role": "verifier"}
    )
    assert latest_suggestion(db, other) is None


@pytest.mark.db
def test_latest_suggestion_tolerates_missing_gate_keys(db):
    """The row shape is P3's and may still move: a key P3-T10 does not write
    becomes `None`, never a `KeyError`."""
    alert_id = _queued(db)
    _insert_run(
        db,
        alert_id,
        result={"suggested_action": "needs_review", "confidence": "low"},
        gate_result={},
    )

    suggestion = latest_suggestion(db, alert_id)

    assert suggestion is not None
    # a stored `needs_review` with a `gate_result` that does not name the model's answer: nothing to serve (DEC-217)
    assert suggestion.suggested_action is None
    assert suggestion.confidence == "low"
    assert suggestion.reasons == []
    assert suggestion.gate == {
        "forced": None,
        "forced_by": None,
        "proposed_verdict": None,
        "final_verdict": None,
        "verifier_verdict": None,
        "warnings": [],
        # DEC-225: no `rag_rule` key: Tier 1 is not told that a rule exists
    }
    assert suggestion.correlated_at_analysis is None

    # `facts` present but without `correlated_clusters`; `gate_result` NULL altogether.
    later = _queued(db)
    _insert_run(db, later, result={"suggested_action": "true_positive"}, gate_result={"facts": {}})
    got = latest_suggestion(db, later)
    assert got is not None and got.correlated_at_analysis is None and got.confidence is None
    nul = _queued(db)
    _insert_run(db, nul, result={"suggested_action": "true_positive"}, gate_result=None)
    got = latest_suggestion(db, nul)
    assert got is not None and got.gate["forced"] is None and got.correlated_at_analysis is None


@pytest.mark.db
def test_latest_suggestion_reads_p3_t10_shape_and_latest_proposer_wins(db):
    alert_id = _queued(db)
    run_id = _insert_run(db, alert_id)

    suggestion = latest_suggestion(db, alert_id)

    assert isinstance(suggestion, Suggestion)
    assert suggestion.run_id == run_id
    assert suggestion.suggested_action == "false_positive"
    assert suggestion.confidence == "high"
    assert suggestion.reasons == [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}]
    assert suggestion.gate == {
        "forced": False,
        "forced_by": [],
        "proposed_verdict": "false_positive",
        "final_verdict": "false_positive",
        "verifier_verdict": "false_positive",
        "warnings": [],
        # DEC-225: no `rag_rule` key, whatever the stored document says (`GATE` is a run from before the key)
    }
    assert suggestion.correlated_at_analysis == 2
    assert isinstance(suggestion.created_at, datetime)
    assert set(suggestion.to_dict()) == {
        "run_id",
        "suggested_action",
        "confidence",
        "reasons",
        "gate",
        "correlated_at_analysis",
        "created_at",
    }

    # The verifier row written one second later is not the suggestion...
    _insert_run(db, alert_id, role="verifier", result=VERIFIER_RESULT, gate_result={}, offset_s=1)
    assert latest_suggestion(db, alert_id).run_id == run_id
    # ...a later proposer row is, and `reasons` is capped at 10.
    twelve = [
        {"claim": f"c{i}", "quote": "q", "source": "kb_playbook", "extra": i} for i in range(12)
    ]
    later = _insert_run(
        db,
        alert_id,
        result={**RESULT, "suggested_action": "needs_review", "reasons": twelve},
        gate_result={**GATE, "forced": True, "forced_by": ["rule_check"], "warnings": ["w"]},
        offset_s=2,
    )
    got = latest_suggestion(db, alert_id)
    assert got.run_id == later
    # stored `needs_review` (a version 1 run), served as the model's own answer, `GATE`'s `false_positive`
    assert got.suggested_action == "false_positive"
    assert len(got.reasons) == 10
    assert got.reasons[0] == {"claim": "c0", "quote": "q", "source": "kb_playbook"}
    assert got.gate["forced"] is True and got.gate["forced_by"] == ["rule_check"]
    assert got.gate["warnings"] == ["w"]


class _CountingConn:
    """The connection, counting `execute` calls (what a reader costs in statements)."""

    def __init__(self, conn: psycopg.Connection) -> None:
        self._conn = conn
        self.n = 0

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        self.n += 1
        return self._conn.execute(*args, **kwargs)


@pytest.mark.db
def test_latest_suggestions_equals_latest_suggestion_for_each_alert_in_one_statement(db):
    """P11-T20 row 20. The batched reader answers, for each id, exactly what `latest_suggestion`
    answers for it, whatever ① left behind: no run, a failed run (`result` NULL), a verifier row
    only, one run, several runs (the latest proposer wins, a later verifier row does not count),
    a failed run AFTER a good one (the failed one is the latest, so there is no suggestion; the
    older good run does not stand in), a blind-arm alert (neither reader hides anything:
    `visibility.strip` does that, in the readers an analyst reaches) and a run with more than ten
    reasons. It costs one statement however many ids, and none for no ids."""
    no_run = _queued(db)
    failed = _queued(db)
    _insert_run(db, failed, result=None, gate_result={"error": "schema"}, stopped_by="schema")
    verifier_only = _queued(db)
    _insert_run(db, verifier_only, role="verifier", result=VERIFIER_RESULT, gate_result={})
    one = _queued(db)
    _insert_run(db, one)
    several = _queued(db)
    _insert_run(db, several, result={**RESULT, "suggested_action": "true_positive"}, offset_s=0)
    _insert_run(db, several, result={**RESULT, "suggested_action": "needs_review"}, offset_s=5)
    _insert_run(db, several, role="verifier", result=VERIFIER_RESULT, gate_result={}, offset_s=9)
    failed_last = _queued(db)
    _insert_run(db, failed_last, offset_s=0)
    _insert_run(db, failed_last, result=None, gate_result=None, stopped_by="linter", offset_s=3)
    blind = _queued(db, suggestion_visible=False)
    _insert_run(db, blind, result={**RESULT, "suggested_action": "true_positive"})
    twelve = _queued(db)
    reasons = [{"claim": f"c{i}", "quote": "q", "source": "kb_playbook"} for i in range(12)]
    _insert_run(db, twelve, result={**RESULT, "reasons": reasons})
    ids = [no_run, failed, verifier_only, one, several, failed_last, blind, twelve]

    batched = latest_suggestions(db, [*ids, "no-such-alert", one])  # a stranger and a repeat

    per_id = {alert_id: latest_suggestion(db, alert_id) for alert_id in ids}
    assert batched == {alert_id: got for alert_id, got in per_id.items() if got is not None}
    # and the seeds are not all alike: the comparison above is not two empty answers
    assert set(batched) == {one, several, blind, twelve}
    assert (
        batched[several].suggested_action == "false_positive"
    )  # served: stored `needs_review`, GATE's proposed
    assert failed_last not in batched and len(batched[twelve].reasons) == 10

    counting = _CountingConn(db)
    assert latest_suggestions(counting, ids) == batched and counting.n == 1
    counting.n = 0
    assert latest_suggestions(counting, ids[:2]) == {} and counting.n == 1
    counting.n = 0
    assert latest_suggestions(counting, []) == {} and counting.n == 0


def _insert_tied_run(
    conn: psycopg.Connection, alert_id: str, run_id: str, action: str | None
) -> None:
    """A proposer run with a chosen `run_id`, at THIS transaction's `now()`: every call inside one
    test has the same `created_at`, so the rows tie. `action=None` is a failed run (no `result`)."""
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result, stopped_by, created_at) "
        "VALUES (%s, 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', %s::jsonb, %s, now())",
        (
            run_id,
            alert_id,
            None if action is None else json.dumps({**RESULT, "suggested_action": action}),
            None if action is None else json.dumps(GATE),
            "schema" if action is None else None,
        ),
    )


def _tied_run_id(slot: int, rank: int) -> str:
    """A uuid per (alert slot, rank): within one slot a higher `rank` is a higher `run_id`."""
    return f"00000000-0000-0000-0000-{slot:08x}{rank:04x}"


def _seed_tied_proposer_runs(db) -> dict[str, str]:
    """Six queue alerts, each with three proposer runs at the same `created_at`, inserted in each of
    the six orders of their ids, so that no rule of the form "the first / the last row met" can
    pass. The highest id is `true_positive`. Returns `{alert_id: that run's id}`."""
    actions = {1: "false_positive", 2: "needs_review", 3: "true_positive"}
    expected: dict[str, str] = {}
    for slot, order in enumerate(itertools.permutations(actions), start=1):
        alert_id = _queued(db)
        for rank in order:
            _insert_tied_run(db, alert_id, _tied_run_id(slot, rank), actions[rank])
        expected[alert_id] = _tied_run_id(slot, 3)
    return expected


@pytest.mark.db
def test_proposer_runs_at_one_instant_are_broken_by_run_id_in_both_readers(db):
    """P11-T20 row 32 (P11-T20 review m1). Two proposer runs with the same `created_at` have no
    "latest": without a second sort key the database returns whichever it meets first, and the
    two readers could name different runs (the digest and the alert page showing different ①
    verdicts). The tie-break is `run_id DESC`, in `latest_suggestion` AND in `latest_suggestions`
    (and in the queue's own join: the next test)."""
    expected = _seed_tied_proposer_runs(db)
    for alert_id, run_id in expected.items():
        got = latest_suggestion(db, alert_id)
        assert got is not None and got.run_id == run_id, alert_id
        assert got.suggested_action == "true_positive"
    batched = latest_suggestions(db, list(expected))
    assert {alert_id: s.run_id for alert_id, s in batched.items()} == expected

    # The tie-break picks the run, and the run is judged after: the highest id FAILED, so there is
    # no suggestion, as for any failed latest run (an older good run does not stand in).
    failed_high = _queued(db)
    _insert_tied_run(db, failed_high, _tied_run_id(9, 3), None)
    _insert_tied_run(db, failed_high, _tied_run_id(9, 1), "true_positive")
    _insert_tied_run(db, failed_high, _tied_run_id(9, 2), "needs_review")
    assert latest_suggestion(db, failed_high) is None
    assert failed_high not in latest_suggestions(db, [failed_high, *expected])


@pytest.mark.db
def test_the_queue_row_shows_the_same_run_as_the_alert_page_when_runs_tie(db):
    """P11-T20 row 32, the third reader (`_QUEUE_SQL`'s LATERAL join). The queue list picks "the
    latest proposer run" too, and with a tie and no second sort key it named whichever run the
    database met first, so a queue row and the alert page (`latest_suggestion`) could show different
    runs. The same six tied alerts as the two readers' test: each queue row carries the run with
    the highest `run_id`, which is the run `latest_suggestion` answers for it."""
    expected = _seed_tied_proposer_runs(db)
    failed_high = _queued(db)  # the highest id FAILED: the row shows that run, with no action
    _insert_tied_run(db, failed_high, _tied_run_id(9, 3), None)
    _insert_tied_run(db, failed_high, _tied_run_id(9, 1), "true_positive")
    for alert_id, run_id in expected.items():
        row = _row(db, alert_id)
        assert (row["run_id"], row["suggested_action"]) == (run_id, "true_positive"), alert_id
        assert row["run_id"] == latest_suggestion(db, alert_id).run_id
    row = _row(db, failed_high)
    assert (row["run_id"], row["suggested_action"]) == (_tied_run_id(9, 3), None)
    assert latest_suggestion(db, failed_high) is None  # the alert page agrees: no suggestion


# ---------------------------------------------------------------------------
# get_alert_view
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_view_blind_undecided_has_no_suggestion_then_decided_has_it(db):
    _seed_user(db)
    alert_id = _queued(db, suggestion_visible=False, risk_score=30)
    run_id = _insert_run(db, alert_id)

    view = get_alert_view(db, alert_id)
    assert view is not None
    assert "suggestion" not in view  # an llm_runs row exists — it is not in the response
    assert "triage_status" not in view
    assert view["suggestion_visible"] is False
    assert view["status"] == "queued_tier1"
    assert "risk_score" not in view
    assert view["risk_band"] == "Vừa"
    assert view["acknowledged_by_name"] is None

    acknowledge(db, alert_id, USER_ID)  # tier1_active: still undecided, still blind
    view = get_alert_view(db, alert_id)
    assert "suggestion" not in view
    assert view["status"] == "tier1_active"
    assert view["acknowledged_by_name"] == USER_NAME
    assert isinstance(view["acknowledged_at"], datetime)

    decide(
        db,
        alert_id,
        USER_ID,
        decision="closed_benign",
        reason="benign",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    view = get_alert_view(db, alert_id)
    assert view["status"] == "closed_benign"
    assert view["suggestion"]["suggested_action"] == "false_positive"
    assert view["suggestion"]["run_id"] == run_id
    assert view["suggestion"]["correlated_at_analysis"] == 2
    assert view["triage_status"] == "pending"
    assert "risk_score" not in view


@pytest.mark.db
def test_view_blind_undecided_hides_triaged_count_and_a_decision_brings_it_back(db):
    """R17 / DEC-101: the detail JSON carries `triaged_count` (the view never computes
    `needs_retriage`), and on a blind head that number says "① ran"."""
    _seed_user(db)
    alert_id = _queued(db, suggestion_visible=False, risk_score=30)
    _set(db, alert_id, triaged_count=1)  # ① has run once

    view = get_alert_view(db, alert_id)
    assert view is not None
    assert "triaged_count" not in view and "needs_retriage" not in view
    assert view["occurrence_count"] == 1

    acknowledge(db, alert_id, USER_ID)  # tier1_active: still undecided, still blind
    view = get_alert_view(db, alert_id)
    assert "triaged_count" not in view and "needs_retriage" not in view

    decide(
        db,
        alert_id,
        USER_ID,
        decision="closed_benign",
        reason="benign",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    view = get_alert_view(db, alert_id)
    assert view["status"] == "closed_benign"
    assert view["triaged_count"] == 1  # decide() sets it to the occurrence count it saw


@pytest.mark.db
def test_archiving_a_blind_head_does_not_reveal_what_the_model_said(db):
    """INT-T03 / DEC-212, through the real `archive_before`: an archived head is no decision, so the
    alert page still hides ① from it - the suggestion, the run, the triage state and the counts - on
    the blind arm, whether it was queued or held (`tier1_active`). The visible arm keeps its view.
    """
    from datetime import UTC, timedelta

    from app.domain.transitions import archive_before

    _seed_user(db)
    queued = _queued(db, suggestion_visible=False, risk_score=30)
    held = _queued(db, suggestion_visible=False, risk_score=31)
    acknowledge(db, held, USER_ID)
    visible = _queued(db, suggestion_visible=True, risk_score=32)
    for alert_id in (queued, held, visible):
        _insert_run(db, alert_id)
        _set(db, alert_id, triaged_count=1, triage_status="ready")

    counts = archive_before(
        db, before=datetime.now(UTC) + timedelta(hours=1), reason="DEC-212 test"
    )
    assert counts.by_status["queued_tier1"] >= 2 and counts.by_status["tier1_active"] >= 1

    for alert_id in (queued, held):
        view = get_alert_view(db, alert_id)
        assert view is not None
        assert view["status"] == "archived"
        for key in ("suggestion", "triage_status", "triaged_count", "needs_retriage", "run_id"):
            assert key not in view, (alert_id, key)
        assert "false_positive" not in repr(view)  # what the stored ① run said
    seen = get_alert_view(db, visible)
    assert seen["status"] == "archived"
    assert seen["suggestion"]["suggested_action"] == "false_positive"


@pytest.mark.db
def test_view_visible_arm_keeps_triaged_count(db):
    alert_id = _queued(db, suggestion_visible=True)
    _set(db, alert_id, triaged_count=1)

    view = get_alert_view(db, alert_id)

    assert view["triaged_count"] == 1


# --- INT-T02 item 2 / DEC-211 R6: why ① stopped, in the alert view -------------------------------------


@pytest.mark.db
def test_view_says_why_the_newest_proposer_run_stopped(db):
    """A 402 leaves one proposer row with no result and `stopped_by='unavailable'`: `suggestion` is
    `None` (an older good run does not stand in) and `llm_stopped_by` names the reason, so the
    alert page can say more than "① đã chạy nhưng không có đề xuất"."""
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, offset_s=0)  # an older run, with a result
    _insert_run(db, alert_id, result=None, gate_result=None, stopped_by="unavailable", offset_s=5)

    view = get_alert_view(db, alert_id)

    assert view["suggestion"] is None
    assert view["llm_stopped_by"] == "unavailable"


@pytest.mark.db
def test_view_stop_reason_is_none_when_the_newest_proposer_run_has_a_result(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result=None, gate_result=None, stopped_by="cap", offset_s=0)
    _insert_run(db, alert_id, offset_s=5)  # the newest run succeeded

    view = get_alert_view(db, alert_id)

    assert view["suggestion"]["suggested_action"] == "false_positive"
    assert "llm_stopped_by" in view and view["llm_stopped_by"] is None


@pytest.mark.db
def test_view_stop_reason_is_none_with_no_run_and_ignores_the_verifier_row(db):
    never_ran = _queued(db, suggestion_visible=True)
    assert get_alert_view(db, never_ran)["llm_stopped_by"] is None

    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, offset_s=0)
    _insert_run(  # a verifier failure is the proposer's row's business, not this key's
        db, alert_id, role="verifier", result=None, stopped_by="schema", offset_s=5
    )
    assert get_alert_view(db, alert_id)["llm_stopped_by"] is None


@pytest.mark.db
def test_latest_stopped_by_reads_the_run_latest_suggestion_reads(db):
    alert_id = _queued(db)
    assert queue.latest_stopped_by(db, alert_id) is None  # no run
    _insert_run(db, alert_id, result=None, gate_result=None, stopped_by="schema", offset_s=0)
    assert queue.latest_stopped_by(db, alert_id) == "schema"
    assert latest_suggestion(db, alert_id) is None  # the same newest run, judged the same way
    _insert_run(db, alert_id, offset_s=5)
    assert queue.latest_stopped_by(db, alert_id) is None
    assert latest_suggestion(db, alert_id) is not None


@pytest.mark.db
def test_view_of_a_duplicate_carries_its_heads_stop_reason(db):
    head = _queued(db, suggestion_visible=True)
    duplicate = _duplicate(db, head)
    _insert_run(db, head, result=None, gate_result=None, stopped_by="unavailable")

    assert get_alert_view(db, duplicate)["llm_stopped_by"] == "unavailable"


@pytest.mark.db
def test_view_blind_undecided_does_not_say_why_the_model_stopped_and_a_decision_brings_it_back(db):
    """DEC-101: on the blind arm, "① gave up, and for this reason" says as much as "① ran". The
    key goes with the other ① keys; the control is the same head once it is decided."""
    _seed_user(db)
    alert_id = _queued(db, suggestion_visible=False, risk_score=30)
    _insert_run(db, alert_id, result=None, gate_result=None, stopped_by="unavailable")
    _set(db, alert_id, triage_status="unavailable")

    view = get_alert_view(db, alert_id)
    assert "llm_stopped_by" not in view and "triage_status" not in view
    assert "suggestion" not in view
    assert "unavailable" not in json.dumps(view, default=str)  # not as a value under any other key
    assert view["suggestion_visible"] is False

    acknowledge(db, alert_id, USER_ID)  # still undecided, still blind
    assert "llm_stopped_by" not in get_alert_view(db, alert_id)

    decide(
        db,
        alert_id,
        USER_ID,
        decision="closed_benign",
        reason="benign",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    decided = get_alert_view(db, alert_id)
    assert decided["status"] == "closed_benign"
    assert decided["llm_stopped_by"] == "unavailable"  # evaluation material once a person decided


@pytest.mark.db
@pytest.mark.parametrize("suggestion_visible", [True, False], ids=["visible", "blind"])
def test_view_labeling_mode_never_has_the_stop_reason(db, suggestion_visible):
    alert_id = _queued(db, suggestion_visible=suggestion_visible)
    _insert_run(db, alert_id, result=None, gate_result=None, stopped_by="unavailable")

    labelling = get_alert_view(db, alert_id, mode="labeling")

    assert "llm_stopped_by" not in set(_walk_keys(labelling))
    assert "unavailable" not in json.dumps(labelling, default=str)
    # the control: the analyst view of the same head has it on the visible arm
    analyst = get_alert_view(db, alert_id)
    assert ("llm_stopped_by" in analyst) is suggestion_visible


def test_the_stop_reason_key_is_hidden_on_the_blind_arm_and_from_the_labeller_twice():
    """By name in `ANALYST_HIDE` (so in `LABELING_DENYLIST`, which includes it), and by the `llm_`
    prefix the labelling page drops at any depth: removing it from the set would still not give it
    to a labeller."""
    assert "llm_stopped_by" in ANALYST_HIDE and "llm_stopped_by" in LABELING_DENYLIST
    assert "llm_stopped_by".startswith(LABELING_PREFIXES)
    view = {"suggestion_visible": False, "status": "queued_tier1", "llm_stopped_by": "unavailable"}
    blind = visibility.strip(view, status="queued_tier1", suggestion_visible=False, mode="analyst")
    assert "llm_stopped_by" not in blind
    labelled = visibility.strip(view, status="closed_fp", suggestion_visible=True, mode="labeling")
    assert "llm_stopped_by" not in labelled


@pytest.mark.db
def test_view_duplicate_resolves_to_head(db):
    head = _queued(db)
    duplicate = _duplicate(db, head)

    view = get_alert_view(db, duplicate)

    assert view is not None
    assert view["alert_id"] == head
    assert view["requested_alert_id"] == duplicate
    assert view["duplicate_of"] is None
    assert view["status"] == "queued_tier1"

    direct = get_alert_view(db, head)
    assert direct["alert_id"] == head and direct["requested_alert_id"] == head
    assert get_alert_view(db, "p4t02-does-not-exist") is None


@pytest.mark.db
def test_view_targeted_accounts_correlation_playbook(db):
    head = _queued(db)  # alert_user 'user1', agent 'user1-IA1803'
    _duplicate(db, head, alert_user="root")
    _duplicate(db, head, alert_user=None)
    _duplicate(db, head, alert_user="user1")
    other = _queued(db, rule_id="5710", alert_time=_T + timedelta(minutes=30))  # same agent, ±2h
    _queued(db, alert_time=_T + timedelta(hours=5))  # outside the window
    unrelated = _queued(db, agent_name="elsewhere", alert_user="nobody", srcip="198.51.100.7")

    view = get_alert_view(db, head)

    assert view["targeted_accounts"] == ["root", "user1"]
    rows = view["correlation"]["rows"]
    assert [(row["rule_id"], row["status"], row["cluster_count"]) for row in rows] == [
        ("5710", "queued_tier1", 1)
    ]
    assert isinstance(rows[0]["first_seen"], datetime)
    assert view["correlated_now"] == 1
    samples = view["correlation"]["samples"]
    assert [sample["alert_id"] for sample in samples] == [other]
    assert samples[0]["status"] == "queued_tier1"  # an analyst may see other clusters' status
    assert unrelated not in {sample["alert_id"] for sample in samples}
    assert view["playbook"] is not None
    assert view["playbook"] == get_playbook("ssh_brute_force")
    assert view["category"] == "ssh_brute_force"
    assert view["occurrence_count"] == 1
    assert view["raw_log"] == _CANONICAL.raw_log


@pytest.mark.db
def test_view_unknown_category_has_no_playbook(db):
    alert_id = _queued(db, category="unknown", categories=(), resolved_by="none")
    view = get_alert_view(db, alert_id)
    assert view["playbook"] is None
    assert view["category"] == "unknown"


@pytest.mark.db
def test_view_labeling_mode_has_no_forbidden_keys_anywhere(db):
    """P6-T02's second layer: the labelling page's dict is the analyst view
    passed through `strip(mode="labeling")` — nothing from the denylist at any
    depth, no `source` value token outside the free-text fields (`raw_log`,
    `description`, and the KB `playbook`), whatever the head's flags say."""
    _seed_user(db)
    head = _queued(db, suggestion_visible=True, source="replay")
    _insert_run(db, head)
    _queued(db, rule_id="5710", alert_time=_T + timedelta(minutes=30), source="lab")  # correlated

    view = get_alert_view(db, head, mode="labeling")

    assert view is not None
    keys = set(_walk_keys(view))
    assert not (keys & LABELING_DENYLIST), keys & LABELING_DENYLIST
    assert not [key for key in keys if key.startswith(LABELING_PREFIXES)]
    assert "risk_score" not in view and "risk_band" not in view
    assert "suggestion" not in view and "source" not in view and "status" not in view
    assert "triaged_count" not in view and "needs_retriage" not in view  # DEC-101
    assert view["occurrence_count"] == 1
    assert view["correlation"]["rows"] and view["correlation"]["samples"]
    for row in view["correlation"]["rows"]:
        assert "status" not in row
    for sample in view["correlation"]["samples"]:
        assert "status" not in sample and "source" not in sample
    free_text = frozenset({"raw_log", "description", "playbook"})
    for path, leaf in _walk_string_values(view, skip_keys=free_text):
        for token in ("replay", "wazuh", "lab"):
            assert token not in leaf, f"{token!r} at {path}: {leaf!r}"
    assert view["alert_id"] == head and view["playbook"]

    # The control: the same head's analyst view does carry what labeling strips.
    analyst = get_alert_view(db, head)
    assert analyst["source"] == "replay"
    assert analyst["suggestion"]["suggested_action"] == "false_positive"
    assert analyst["correlation"]["rows"][0]["status"] == "queued_tier1"
