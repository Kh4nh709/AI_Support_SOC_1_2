"""app.tier2.conclude — `submit()` over `domain.conclude_case`, and
`case_notes` (`add_note`/`list_notes`). P5-T06.

Every conclusion maps to the right `alerts.status`; the fan-out reaches every
duplicate of every head (`test_conclude_fanout_reaches_every_duplicate`, named
for acceptance 1); an already-concluded case, an empty reason and an unknown
conclusion each raise before any row is touched; the 5 s statement timeout is
set before `domain.conclude_case` runs; notes reject an empty or over-cap
body, are never audited, and never supply `note_id` (migration 015 note (4)
— the IDENTITY column assigns it).
"""

from __future__ import annotations

import hashlib
import itertools
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from app.tier2 import conclude

pytestmark = pytest.mark.db

_PAST = datetime(2026, 1, 1, tzinfo=UTC)
_counter = itertools.count()

# ---------------------------------------------------------------------------
# Minimal fixture helpers — this file's own, trimmed to what conclude_case's
# fan-out actually reads/writes (status, case_id, duplicate_of, closed_at,
# sealed_at); test_transitions.py's `_insert_alert` covers the full 51-column
# row and is not imported here (own test file, own fixtures — test_labels.py
# and test_transitions.py do the same rather than share).
# ---------------------------------------------------------------------------


def _make_user(conn: psycopg.Connection, *, role: str = "tier2") -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, f"user-{user_id[:8]}", "Test Analyst", role),
    )
    return user_id


def _make_case(
    conn: psycopg.Connection,
    user_id: str,
    *,
    status: str = "investigating",
    concluded_at=None,
    concluded_by=None,
    conclusion_reason=None,
) -> str:
    case_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO cases (case_id, title, status, severity, created_by, concluded_at, "
        "concluded_by, conclusion_reason) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (case_id, "case", status, "high", user_id, concluded_at, concluded_by, conclusion_reason),
    )
    return case_id


def _insert_alert(
    conn: psycopg.Connection,
    *,
    status: str,
    case_id: str | None = None,
    duplicate_of: str | None = None,
    occurrence_count: int = 1,
    closed_at=None,
    sealed_at=None,
) -> str:
    """The twelve NOT NULL-without-default columns plus whatever lifecycle
    columns this test needs — everything else takes its schema default."""
    alert_id = f"p5t06-{next(_counter)}-{uuid.uuid4()}"
    conn.execute(
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, "
        "agent_name, alert_time, category, resolved_by, mapping_version, "
        "event_bucket_hash, raw_payload, status, duplicate_of, occurrence_count, "
        "case_id, closed_at, sealed_at) "
        "VALUES (%s, '40112', 10, 'high', 'SSH brute force', 'agent-1', now(), "
        "'brute_force', 'rule_groups', 'v1', %s, '{}'::jsonb, %s, %s, %s, %s, %s, %s)",
        (
            alert_id,
            hashlib.sha256(alert_id.encode()).hexdigest(),
            status,
            duplicate_of,
            occurrence_count,
            case_id,
            closed_at,
            sealed_at,
        ),
    )
    return alert_id


def _alert_status(conn: psycopg.Connection, alert_id: str) -> str:
    return conn.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[0]


# ---------------------------------------------------------------------------
# submit() — the three conclusions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "conclusion,alert_status",
    [
        ("concluded_fp", "closed_fp"),
        ("concluded_policy_violation", "closed_benign"),
        ("confirmed_incident", "closed_confirmed"),
    ],
)
def test_submit_maps_conclusion_to_alert_status(db, conclusion, alert_status):
    user = _make_user(db)
    case_id = _make_case(db, user)
    head = _insert_alert(db, status="escalated_tier2", case_id=case_id)

    conclude.submit(db, case_id, user, conclusion=conclusion, reason="because")

    assert _alert_status(db, head) == alert_status
    case_status = db.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()[
        0
    ]
    assert case_status == conclusion


def test_conclude_fanout_reaches_every_duplicate(db):
    """2 heads, 5 duplicates each — all 12 rows move and `sealed_at` is set
    (`docs/phase-7-tier2.md` detail 1: *"Thiếu vế này, hàng nghìn bản sao ở
    lại trạng thái cũ"*)."""
    user = _make_user(db)
    case_id = _make_case(db, user)
    heads = [_insert_alert(db, status="escalated_tier2", case_id=case_id) for _ in range(2)]
    dups = [
        _insert_alert(
            db,
            status="duplicate",
            duplicate_of=head,
            case_id=case_id,
            closed_at=_PAST,
            sealed_at=_PAST,
        )
        for head in heads
        for _ in range(5)
    ]
    all_ids = heads + dups
    assert len(all_ids) == 12

    conclude.submit(db, case_id, user, conclusion="concluded_fp", reason="scanner cluster")

    rows = db.execute(
        "SELECT alert_id, status, sealed_at FROM alerts WHERE alert_id = ANY(%s)",
        (all_ids,),
    ).fetchall()
    assert len(rows) == 12
    for alert_id, status, sealed_at in rows:
        assert status == "closed_fp", alert_id
        assert sealed_at is not None, alert_id


def test_submit_sets_statement_timeout_before_calling_domain(db, monkeypatch):
    """Design note 4 red step (b): remove the `SET LOCAL` and this observes a
    different value (the connection's ambient default) instead of `5s`."""
    user = _make_user(db)
    case_id = _make_case(db, user)
    observed: dict[str, str] = {}

    def _spy(conn, cid, uid, *, conclusion, reason):
        observed["timeout"] = conn.execute("SHOW statement_timeout").fetchone()[0]

    monkeypatch.setattr(conclude.transitions, "conclude_case", _spy)

    conclude.submit(db, case_id, user, conclusion="concluded_fp", reason="x")

    assert observed["timeout"] == "5s"


def test_submit_rejects_unknown_conclusion(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    with pytest.raises(ValueError, match="conclusion"):
        conclude.submit(db, case_id, user, conclusion="bogus", reason="x")


def test_submit_rejects_empty_reason(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    with pytest.raises(ValueError, match="reason"):
        conclude.submit(db, case_id, user, conclusion="concluded_fp", reason="   ")


def test_submit_raises_conflict_with_current_status_when_already_concluded(db):
    user = _make_user(db)
    other = _make_user(db)
    case_id = _make_case(
        db,
        user,
        status="concluded_fp",
        concluded_at=_PAST,
        concluded_by=other,
        conclusion_reason="prior",
    )

    with pytest.raises(conclude.ConcludeConflict) as excinfo:
        conclude.submit(db, case_id, user, conclusion="confirmed_incident", reason="x")

    exc = excinfo.value
    assert exc.status == "concluded_fp"
    assert str(exc.concluded_by) == other
    assert exc.concluded_at is not None


def test_submit_raises_unknown_case_for_a_case_that_does_not_exist(db):
    """A case that never existed is 404, not 409 — distinct from
    `ConcludeConflict`, which is only for a case that exists but has left
    `investigating` (review round 1, item 3)."""
    user = _make_user(db)
    missing = str(uuid.uuid4())
    with pytest.raises(conclude.UnknownCase) as excinfo:
        conclude.submit(db, missing, user, conclusion="concluded_fp", reason="x")
    assert excinfo.value.case_id == missing


def test_submit_rejects_a_nul_byte_in_reason(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    with pytest.raises(ValueError, match="reason"):
        conclude.submit(db, case_id, user, conclusion="concluded_fp", reason="x\x00y")


def test_submit_caps_the_reason_at_500_characters_as_tier1_does(db):
    """P11-T20 row 12: 501 characters is refused with Tier-1's message, before any SQL, and the
    case stays `investigating`; 500 is stored; surrounding whitespace is not counted (the stored
    reason is the stripped one, as in `tier1/decide.py`), so padding cannot get round the cap."""
    user = _make_user(db)
    refused = _make_case(db, user)
    with pytest.raises(ValueError, match=r"^reason: must be 1-500 characters$"):
        conclude.submit(db, refused, user, conclusion="concluded_fp", reason="x" * 501)
    with pytest.raises(ValueError, match=r"^reason: must be 1-500 characters$"):
        conclude.submit(db, refused, user, conclusion="concluded_fp", reason=" " + "é" * 501)
    status, reason = db.execute(
        "SELECT status, conclusion_reason FROM cases WHERE case_id = %s", (refused,)
    ).fetchone()
    assert (status, reason) == ("investigating", None)

    at_the_cap = _make_case(db, user)
    conclude.submit(db, at_the_cap, user, conclusion="concluded_fp", reason="x" * 500)
    padded = _make_case(db, user)
    conclude.submit(db, padded, user, conclusion="concluded_fp", reason="\n  " + "y" * 500 + " \t ")
    stored = {
        str(case_id): reason
        for case_id, reason in db.execute(
            "SELECT case_id, conclusion_reason FROM cases WHERE case_id = ANY(%s)",
            ([at_the_cap, padded],),
        ).fetchall()
    }
    assert stored == {at_the_cap: "x" * 500, padded: "y" * 500}


# ---------------------------------------------------------------------------
# add_note / list_notes
# ---------------------------------------------------------------------------


def test_add_note_rejects_empty_body(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    with pytest.raises(ValueError, match="body"):
        conclude.add_note(db, case_id, user, "   ")


def test_add_note_rejects_body_over_the_cap(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    with pytest.raises(ValueError, match="body"):
        conclude.add_note(db, case_id, user, "x" * (conclude.NOTE_BODY_MAX_BYTES + 1))


def test_add_note_rejects_a_nul_byte(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    with pytest.raises(ValueError, match="body"):
        conclude.add_note(db, case_id, user, "a\x00b")


def test_add_note_unknown_case_raises(db):
    user = _make_user(db)
    with pytest.raises(conclude.UnknownCase):
        conclude.add_note(db, str(uuid.uuid4()), user, "a note")


def test_add_note_writes_no_audit_event(db):
    """Design note 2: a note is not a decision — `case.note_added` does not
    exist in the 28 names (016's 27 and 019's `admin.settings_changed`), and this function
    writes none."""
    user = _make_user(db)
    case_id = _make_case(db, user)
    before = db.execute(
        "SELECT count(*) FROM audit_events WHERE subject_id = %s", (case_id,)
    ).fetchone()[0]

    conclude.add_note(db, case_id, user, "watch this")

    after = db.execute(
        "SELECT count(*) FROM audit_events WHERE subject_id = %s", (case_id,)
    ).fetchone()[0]
    assert after == before == 0


def test_add_note_does_not_supply_note_id(db):
    """Red step (c): a hand-supplied `note_id` (instead of letting the
    IDENTITY column assign it) collides on the second `INSERT` — this
    asserts the two ids the column assigns are distinct and increasing."""
    user = _make_user(db)
    case_id = _make_case(db, user)
    first = conclude.add_note(db, case_id, user, "first note")
    second = conclude.add_note(db, case_id, user, "second note")
    assert second > first


def test_list_notes_orders_by_created_at_then_note_id(db):
    user = _make_user(db)
    case_id = _make_case(db, user)
    a = conclude.add_note(db, case_id, user, "a")
    b = conclude.add_note(db, case_id, user, "b")

    notes = conclude.list_notes(db, case_id)

    assert [n.note_id for n in notes] == sorted([a, b])
    assert [n.body for n in notes] == ["a", "b"]
    assert all(str(n.case_id) == case_id for n in notes)
