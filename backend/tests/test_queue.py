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
from app.tier1.queue import (
    PAGE_SIZE_DEFAULT,
    PAGE_SIZE_MAX,
    RETRIAGE_ABS_DELTA,
    RETRIAGE_FACTOR,
    QueuePage,
    Suggestion,
    get_alert_view,
    latest_suggestion,
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
    "forced_by": None,
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


def _all_rows(conn: psycopg.Connection) -> list[dict]:
    """Every queue row, paging through with the maximum page size."""
    rows: list[dict] = []
    page = 1
    while True:
        result = list_queue(conn, page=page, page_size=PAGE_SIZE_MAX)
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
    assert row["suggestion_visible"] is False  # the analyst may know they are on the blind arm
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
        gate_result={"role": "verifier", "compared_to": "false_positive", "proposer_run_id": proposer},
        offset_s=1,
    )

    rows = [row for row in _all_rows(db) if row["alert_id"] == alert_id]
    assert len(rows) == 1
    assert rows[0]["run_id"] == proposer
    assert rows[0]["suggested_action"] == "false_positive"
    assert list_queue(db).total == baseline + 1

    # A later proposer row (a re-triage) is the one that shows; still one row.
    later = _insert_run(
        db, alert_id, role="proposer", result={**RESULT, "suggested_action": "needs_review"}, offset_s=2
    )
    rows = [row for row in _all_rows(db) if row["alert_id"] == alert_id]
    assert len(rows) == 1
    assert rows[0]["run_id"] == later
    assert rows[0]["suggested_action"] == "needs_review"


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
    _insert_run(db, other, role="verifier", result=VERIFIER_RESULT, gate_result={"role": "verifier"})
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
    assert suggestion.suggested_action == "needs_review"
    assert suggestion.confidence == "low"
    assert suggestion.reasons == []
    assert suggestion.gate == {
        "forced": None,
        "forced_by": None,
        "proposed_verdict": None,
        "final_verdict": None,
        "verifier_verdict": None,
        "warnings": [],
    }
    assert suggestion.correlated_at_analysis is None

    # `facts` present but without `correlated_clusters`; `gate_result` NULL altogether.
    later = _queued(db)
    _insert_run(db, later, result={"suggested_action": "escalate"}, gate_result={"facts": {}})
    got = latest_suggestion(db, later)
    assert got is not None and got.correlated_at_analysis is None and got.confidence is None
    nul = _queued(db)
    _insert_run(db, nul, result={"suggested_action": "escalate"}, gate_result=None)
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
        "forced_by": None,
        "proposed_verdict": "false_positive",
        "final_verdict": "false_positive",
        "verifier_verdict": "false_positive",
        "warnings": [],
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
    twelve = [{"claim": f"c{i}", "quote": "q", "source": "kb_playbook", "extra": i} for i in range(12)]
    later = _insert_run(
        db,
        alert_id,
        result={**RESULT, "suggested_action": "needs_review", "reasons": twelve},
        gate_result={**GATE, "forced": True, "forced_by": ["rule_check"], "warnings": ["w"]},
        offset_s=2,
    )
    got = latest_suggestion(db, alert_id)
    assert got.run_id == later
    assert got.suggested_action == "needs_review"
    assert len(got.reasons) == 10
    assert got.reasons[0] == {"claim": "c0", "quote": "q", "source": "kb_playbook"}
    assert got.gate["forced"] is True and got.gate["forced_by"] == ["rule_check"]
    assert got.gate["warnings"] == ["w"]


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
