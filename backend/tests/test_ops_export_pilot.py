"""Tests for eval/ops_export.py's pilot section (P10-T06): the human pilot's per-arm figures.

The seed is one small pilot on a fixed 2011 clock, so every expected number is derived in the
comments below and no other test file's rows or exact counts are touched. Every test seeds inside
the `db` fixture's transaction and never commits, as test_ops_export.py does; the helpers
(`_open`, `_event`, `_run`, ...) are that file's, imported, not copied.

The pilot's clock: `PILOT_START` 2011-03-14T10:00:00Z, `PILOT_END` 15:00:00Z, half-open. Every
event is placed by its offset in seconds from `PILOT_START`.

Blind arm (`suggestion_visible = false`), ① is the latest proposer row's `suggested_action`:

    alert  source  ①               human        ack -> decide   person
    B1     lab     escalate        escalated    120 s           A
    B2     lab     false_positive  false_pos.   300 s           A   (a later verifier row says
                                                                     `escalate`; it is not ①)
    B3     lab     false_positive  benign        60 s           A
    B4     lab     needs_review    false_pos.    30 s           A
    B5     wazuh   escalate        false_pos.   240 s           B
    B6     wazuh   false_positive  false_pos.   120 s           B   (its earlier row said
                                                                     `needs_review`; latest wins)
    B7     wazuh   (result NULL)   benign        60 s           B
    B8     wazuh   (no row)        escalated     90 s           B

Visible arm: V1 lab fp (150 s, A), V2 wazuh escalated (180 s, B), V3 wazuh benign (240 s, B).

Derived, blind: lab 4 decisions (fp 2, benign 1, escalated 1), median of 30/60/120/300 = 90 s;
wazuh 4 (fp 2, benign 1, escalated 1), median of 60/90/120/240 = 105 s; all 8, median of the
eight = 105 s. Agreement: lab denominator 3 (B1, B2, B3), agreed 2 (B1, B2), `needs_review` 1
(B4); wazuh denominator 2 (B5, B6), agreed 1 (B6), no ① result 2 (B7, B8); all 3 of 5.
Visible: lab 1 (150 s); wazuh 2 (median of 180/240 = 210 s); all 3 (median 180 s).
"""

from __future__ import annotations

import re
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from tests.test_ops_export import (
    MARKER,
    TICK,
    UNUSED_DSN,
    _appendix_sql,
    _event,
    _gated,
    _open,
    _run,
    _section,
    _user,
    _window,
    at,
    ops_export,
)

PILOT_START = at(600)
PILOT_END = at(900)
NOT_MEASURED = "not measured: pilot start not given"


def _secs(offset: float | timedelta) -> timedelta:
    return offset if isinstance(offset, timedelta) else timedelta(seconds=offset)


def _t(offset: float | timedelta) -> datetime:
    """`offset` seconds (or a timedelta) after the pilot's start."""
    return PILOT_START + _secs(offset)


def _pilot(end: datetime | None = PILOT_END):
    return ops_export.PilotWindow(PILOT_START, end)


# --- seeding -----------------------------------------------------------------------------------


def _ack(db, alert_id: str, actor: str, when: datetime) -> None:
    _event(db, "alert.acknowledged", alert_id, when, actor_role="analyst", actor_id=actor)


def _close(
    db,
    alert_id: str,
    actor: str,
    when: datetime,
    decision: str,
    seen: tuple[str, str] | None = None,
) -> None:
    """A `tier1.decided` row shaped like `transitions.decide` writes it (`closed_fp`|`closed_benign`),
    with the analyst's free-text reason carrying the marker. `seen` is `(run_id, suggested_action)`
    of the proposer run `queue.latest_suggestion` returned at that moment, or None when it
    returned nothing: the payload records both (`transitions.py`, `llm_run_id`/`llm_suggestion`)."""
    payload = {
        "decision": decision,
        "reason": f"reason {MARKER}",
        "occurrence_count": 1,
        "llm_suggestion": None if seen is None else seen[1],
        "llm_run_id": None if seen is None else seen[0],
        "suggestion_visible": None,
    }
    _event(
        db, "tier1.decided", alert_id, when, actor_role="analyst", actor_id=actor, payload=payload
    )


def _escalate(db, alert_id: str, actor: str, when: datetime) -> None:
    """A `tier1.escalated` row shaped like `transitions.escalate` writes it."""
    payload = {"case_id": str(uuid.uuid4()), "alert_ids": [alert_id], "llm_suggestion": None}
    _event(
        db, "tier1.escalated", alert_id, when, actor_role="analyst", actor_id=actor, payload=payload
    )


def _suggest(db, alert_id: str, action: str, when: datetime) -> str:
    """A proposer row whose `result->>'suggested_action'` is `action`; returns its run_id."""
    _gated(db, alert_id, when, action, forced=False)
    row = db.execute(
        "SELECT run_id FROM llm_runs WHERE subject_id = %s AND role = 'proposer' "
        "AND created_at = %s",
        (alert_id, when),
    ).fetchone()
    return str(row[0])


def _handled(
    db,
    *,
    source: str,
    visible: bool,
    actor: str,
    ack_at: float | timedelta,
    took: float | timedelta,
    outcome: str,
    suggested: str | None = None,
    earlier: tuple[str, ...] = (),
    failed_run: bool = False,
    synthetic: bool = False,
) -> str:
    """One alert acknowledged at `ack_at` s and decided `took` s later. `outcome` is
    `false_positive`, `benign` or `escalated`. ① is what the analyst's console showed: the proposer
    rows `earlier` (oldest first), then `suggested`, all before the pilot, the last one latest;
    None and no `earlier` is no row, and `failed_run` is a latest proposer row with no result."""
    alert_id = _open(db, received_at=at(10), source=source, visible=visible, synthetic=synthetic)
    seen = None  # what `latest_suggestion` returned when the decision was made
    actions = (*earlier, *(() if suggested is None else (suggested,)))
    for number, action in enumerate(actions, start=1):
        seen = (_suggest(db, alert_id, action, at(number)), action)
    if failed_run:
        _run(db, alert_id, at(len(actions) + 1), stopped_by="schema")
        seen = None
    _ack(db, alert_id, actor, _t(ack_at))
    done = _t(_secs(ack_at) + _secs(took))
    if outcome == "escalated":
        _escalate(db, alert_id, actor, done)
    else:
        _close(
            db,
            alert_id,
            actor,
            done,
            "closed_fp" if outcome == "false_positive" else "closed_benign",
            seen,
        )
    return alert_id


def _seed_pilot(db) -> dict:
    a, b = _user(db), _user(db)
    blind = {"visible": False}
    ids = {"A": a, "B": b}

    ids["B1"] = _handled(
        db,
        source="lab",
        actor=a,
        ack_at=60,
        took=120,
        outcome="escalated",
        suggested="escalate",
        **blind,
    )
    ids["B2"] = _handled(
        db,
        source="lab",
        actor=a,
        ack_at=600,
        took=300,
        outcome="false_positive",
        suggested="false_positive",
        **blind,
    )
    # a verifier row, later than the proposer's: it is not ①
    _run(
        db,
        ids["B2"],
        at(3),
        role="verifier",
        gate={"error": "none"},
        result={"suggested_action": "escalate"},
    )
    ids["B3"] = _handled(
        db,
        source="lab",
        actor=a,
        ack_at=1200,
        took=60,
        outcome="benign",
        suggested="false_positive",
        **blind,
    )
    ids["B4"] = _handled(
        db,
        source="lab",
        actor=a,
        ack_at=1800,
        took=30,
        outcome="false_positive",
        suggested="needs_review",
        **blind,
    )
    ids["B5"] = _handled(
        db,
        source="wazuh",
        actor=b,
        ack_at=2400,
        took=240,
        outcome="false_positive",
        suggested="escalate",
        **blind,
    )
    ids["B6"] = _handled(
        db,
        source="wazuh",
        actor=b,
        ack_at=3000,
        took=120,
        outcome="false_positive",
        earlier=("needs_review",),
        suggested="false_positive",  # the latest proposer row wins
        **blind,
    )
    ids["B7"] = _handled(
        db,
        source="wazuh",
        actor=b,
        ack_at=3600,
        took=60,
        outcome="benign",
        failed_run=True,  # a proposer row with no result
        **blind,
    )
    ids["B8"] = _handled(
        db, source="wazuh", actor=b, ack_at=6000, took=90, outcome="escalated", **blind
    )

    ids["V1"] = _handled(
        db,
        source="lab",
        visible=True,
        actor=a,
        ack_at=4200,
        took=150,
        outcome="false_positive",
        suggested="false_positive",
    )
    ids["V2"] = _handled(
        db,
        source="wazuh",
        visible=True,
        actor=b,
        ack_at=4800,
        took=180,
        outcome="escalated",
        suggested="escalate",
    )
    ids["V3"] = _handled(
        db,
        source="wazuh",
        visible=True,
        actor=b,
        ack_at=5400,
        took=240,
        outcome="benign",
        suggested="false_positive",
    )

    # decoys, each of which would move a figure if it were counted
    ids["X1"] = _handled(
        db,
        source="lab",
        actor=a,
        ack_at=-61,
        took=60,  # decided 1 s before
        outcome="false_positive",
        suggested="false_positive",
        **blind,
    )
    ids["X2"] = _handled(
        db,
        source="lab",
        actor=a,
        ack_at=7000,
        took=60,
        outcome="false_positive",
        suggested="false_positive",
        synthetic=True,
        **blind,
    )
    ids["X3"] = _handled(
        db,
        source="lab",
        actor=a,
        ack_at=17000,
        took=1200,  # decided at the end
        outcome="benign",
        suggested="escalate",
        **blind,
    )
    ids["X5"] = _open(db, received_at=at(10), source="lab", visible=False)
    _ack(db, ids["X5"], a, _t(7100))  # acknowledged, never decided
    _event(db, "tier2.concluded", ids["B2"], _t(8000), actor_role="analyst", actor_id=b)
    return ids


def _section6a(text: str) -> str:
    return _section(text, "6a · ")


def _report(db, pilot=...):
    return ops_export.build_report(db, _window(), _pilot() if pilot is ... else pilot)


# --- the figures ---------------------------------------------------------------------------------


@pytest.mark.db
def test_pilot_counts_decisions_by_type_per_arm_and_source(db):
    _seed_pilot(db)
    section = _section6a(_report(db))

    assert (
        "| arm | source | false_positive | benign | escalated | decisions |\n|---|---|---|---|---|---|\n"
        "| blind | wazuh | 2 | 1 | 1 | 4 |\n"
        "| blind | lab | 2 | 1 | 1 | 4 |\n"
        "| blind | all | 4 | 2 | 2 | 8 |\n"
        "| visible | wazuh | 0 | 1 | 1 | 2 |\n"
        "| visible | lab | 1 | 0 | 0 | 1 |\n"
        "| visible | all | 1 | 1 | 1 | 3 |\n"
    ) in section


@pytest.mark.db
def test_pilot_median_acknowledge_to_decide_is_exact_per_arm_and_source(db):
    _seed_pilot(db)
    section = _section6a(_report(db))

    assert (
        "| arm | source | median acknowledge → decide | n (acknowledged in the window) | decisions |\n"
        "|---|---|---|---|---|\n"
        "| blind | wazuh | 1.75 min | 4 | 4 |\n"
        "| blind | lab | 1.50 min | 4 | 4 |\n"
        "| blind | all | 1.75 min | 8 | 8 |\n"
        "| visible | wazuh | 3.50 min | 2 | 2 |\n"
        "| visible | lab | 2.50 min | 1 | 1 |\n"
        "| visible | all | 3.00 min | 3 | 3 |\n"
    ) in section


@pytest.mark.db
def test_blind_agreement_counts_needs_review_apart_and_not_as_a_disagreement(db):
    _seed_pilot(db)
    section = _section6a(_report(db))

    # lab: 4 blind decisions; ① needs_review on B4 is no verdict, so the denominator is 3 not 4
    assert (
        "| source | decisions (n) | ① needs_review (no verdict) | ① no result | denominator | "
        "agreed | agreement |\n|---|---|---|---|---|---|---|\n"
        "| wazuh | 4 | 0 | 2 | 2 | 1 | 0.500 (1 / 2) |\n"
        "| lab | 4 | 1 | 0 | 3 | 2 | 0.667 (2 / 3) |\n"
        "| all | 8 | 1 | 2 | 5 | 3 | 0.600 (3 / 5) |\n"
    ) in section
    assert "① `needs_review` is no verdict" in section


@pytest.mark.db
def test_blind_cross_table_of_the_verdict_by_the_human_decision(db):
    _seed_pilot(db)
    section = _section6a(_report(db))

    # every blind decision is in one row: 8 in all. ① has no `benign`, so B3 (① false_positive,
    # human benign) is a disagreement above and is visible here as a closure, not a miss.
    assert (
        "| source | ① verdict | false_positive | benign | escalated | decisions |\n"
        "|---|---|---|---|---|---|\n"
        "| wazuh | escalate | 1 | 0 | 0 | 1 |\n"
        "| wazuh | false_positive | 1 | 0 | 0 | 1 |\n"
        "| wazuh | needs_review | 0 | 0 | 0 | 0 |\n"
        "| wazuh | no_result | 0 | 1 | 1 | 2 |\n"
        "| lab | escalate | 0 | 0 | 1 | 1 |\n"
        "| lab | false_positive | 1 | 1 | 0 | 2 |\n"
        "| lab | needs_review | 1 | 0 | 0 | 1 |\n"
        "| lab | no_result | 0 | 0 | 0 | 0 |\n"
        "| all | escalate | 1 | 0 | 1 | 2 |\n"
        "| all | false_positive | 2 | 1 | 0 | 3 |\n"
        "| all | needs_review | 1 | 0 | 0 | 1 |\n"
        "| all | no_result | 0 | 1 | 1 | 2 |\n"
    ) in section
    heading = "### ① verdict × human decision, blind arm only (Q33)"
    assert heading in section
    block = section[section.index(heading) :].split("\n### ")[0]
    assert "| visible |" not in block  # the visible arm saw ①: no cross-table for it


@pytest.mark.db
def test_visible_arm_never_has_an_agreement_figure(db):
    # only visible-arm decisions, each one matching ①: there is nothing to agree on the blind arm
    a = _user(db)
    _handled(
        db,
        source="lab",
        visible=True,
        actor=a,
        ack_at=60,
        took=60,
        outcome="false_positive",
        suggested="false_positive",
    )
    _handled(
        db,
        source="wazuh",
        visible=True,
        actor=a,
        ack_at=300,
        took=60,
        outcome="escalated",
        suggested="escalate",
    )
    section = _section6a(_report(db))

    block = section[section.index("### ① agreement with the human, blind arm only") :]
    block = block.split("\n### ")[0]
    for source in ("wazuh", "lab", "all"):
        assert f"| {source} | 0 | 0 | 0 | 0 | 0 | n/a (0 rows) |" in block
    assert "| visible |" not in block
    assert "the visible arm has no agreement figure" in block
    # the visible decisions are in the tables that are not about ①
    assert "| visible | all | 1 | 0 | 1 | 2 |" in section


@pytest.mark.db
def test_the_latest_proposer_row_is_the_verdict_and_a_verifier_row_is_not(db):
    a = _user(db)
    _handled(
        db,
        source="lab",
        visible=False,
        actor=a,
        ack_at=60,
        took=60,
        outcome="false_positive",
        suggested="needs_review",
    )
    late = _open(db, received_at=at(10), source="lab", visible=False)
    _suggest(db, late, "escalate", at(1))
    latest = _suggest(db, late, "false_positive", at(2))
    _run(
        db,
        late,
        at(3),
        role="verifier",
        gate={"error": "none"},
        result={"suggested_action": "escalate"},
    )
    _ack(db, late, a, _t(300))
    _close(db, late, a, _t(360), "closed_fp", (latest, "false_positive"))

    section = _section6a(_report(db))

    # the first alert: needs_review (no verdict); the second: false_positive, agreed
    assert "| lab | 2 | 1 | 0 | 1 | 1 | 1.000 (1 / 1) |" in section


# --- ① as it was when the human decided (the Reviewer's F1) --------------------------------------
#
# The triage job still runs on an alert that was escalated, and a job still running when the human
# decides has a `created_at` (its transaction's start) before the decision, though nobody could
# see its row. So `llm_runs` alone cannot say what ① was at that moment. A `tier1.decided` event
# records it in its payload (`llm_run_id`, `llm_suggestion`); a `tier1.escalated` event does not,
# and takes the latest proposer row created at or before it.

CAVEAT = (
    "escalations: ① taken as the latest run created at or before the decision; a run in flight "
    "at that moment may be included"
)


def _blind_lab(db) -> tuple[str, str]:
    """A blind lab alert and the analyst who will decide it."""
    return _open(db, received_at=at(10), source="lab", visible=False), _user(db)


def _lab_line(db) -> str:
    """The agreement table's `lab` row, alone, for the alerts the test seeded."""
    section = _section6a(_report(db))
    lines = [line for line in section.splitlines() if line.startswith("| lab | ")]
    agreement = [line for line in lines if line.count("|") == 8]  # 7 cells: the agreement table
    assert len(agreement) == 1, lines
    return agreement[0]


@pytest.mark.db
def test_an_escalation_takes_the_latest_proposer_row_at_or_before_it(db):
    # E1: `false_positive` at 1 min, `escalate` created exactly at the decision (inclusive), and
    # `false_positive` created after it: ① was `escalate`, and the escalation agrees.
    e1, a = _blind_lab(db)
    _suggest(db, e1, "false_positive", at(1))
    _ack(db, e1, a, _t(60))
    _escalate(db, e1, a, _t(120))
    _suggest(db, e1, "escalate", _t(120))
    _suggest(db, e1, "false_positive", _t(180))
    # E2: a verifier row after the proposer's is not ①: it was `false_positive`, a disagreement.
    e2, _ = _blind_lab(db)
    _suggest(db, e2, "false_positive", at(1))
    _run(
        db,
        e2,
        at(3),
        role="verifier",
        gate={"error": "none"},
        result={"suggested_action": "escalate"},
    )
    _ack(db, e2, a, _t(300))
    _escalate(db, e2, a, _t(360))

    assert _lab_line(db) == "| lab | 2 | 0 | 0 | 2 | 1 | 0.500 (1 / 2) |"


@pytest.mark.db
def test_a_run_created_after_an_escalation_is_not_the_verdict(db):
    alert, a = _blind_lab(db)
    _suggest(db, alert, "false_positive", at(1))
    _ack(db, alert, a, _t(60))
    _escalate(db, alert, a, _t(120))
    _suggest(db, alert, "escalate", _t(180))  # the job ran on after the escalation

    # ① was `false_positive` when the human escalated: a disagreement, not the later `escalate`
    assert _lab_line(db) == "| lab | 1 | 0 | 0 | 1 | 0 | 0.000 (0 / 1) |"


@pytest.mark.db
def test_a_run_created_after_a_decision_is_not_the_verdict(db):
    alert, a = _blind_lab(db)
    seen = _suggest(db, alert, "escalate", at(1))
    _ack(db, alert, a, _t(60))
    _close(db, alert, a, _t(120), "closed_fp", (seen, "escalate"))
    _suggest(db, alert, "false_positive", _t(180))  # a later run, which would "agree"

    assert _lab_line(db) == "| lab | 1 | 0 | 0 | 1 | 0 | 0.000 (0 / 1) |"


@pytest.mark.db
def test_the_run_a_decision_names_is_the_verdict_even_when_a_run_is_in_flight(db):
    alert, a = _blind_lab(db)
    named = _suggest(db, alert, "false_positive", at(1))
    _ack(db, alert, a, _t(60))
    # a job that started before the decision and committed after it: its `created_at` (its
    # transaction's start) is before the decision, but the analyst's console never had its row
    _suggest(db, alert, "escalate", _t(90))
    _close(db, alert, a, _t(120), "closed_fp", (named, "false_positive"))

    # a time bound alone would take the in-flight `escalate` and disagree; the payload names A
    assert _lab_line(db) == "| lab | 1 | 0 | 0 | 1 | 1 | 1.000 (1 / 1) |"


@pytest.mark.db
def test_a_decision_that_recorded_no_run_has_no_result_even_when_one_is_in_flight(db):
    alert, a = _blind_lab(db)
    _ack(db, alert, a, _t(60))
    _suggest(db, alert, "false_positive", _t(90))  # in flight at the decision, not in the payload
    _close(db, alert, a, _t(120), "closed_fp")  # `llm_run_id` is null: no result at that moment

    assert _lab_line(db) == "| lab | 1 | 0 | 1 | 0 | 0 | n/a (0 rows) |"


@pytest.mark.db
def test_the_escalation_caveat_is_printed_with_the_agreement(db):
    _seed_pilot(db)
    section = _section6a(_report(db))
    block = section[section.index("### ① agreement with the human, blind arm only") :]
    block = block.split("\n### ")[0]

    assert f"- {CAVEAT}" in block
    assert "`llm_suggestion`" in block  # the decided events' own record


@pytest.mark.db
def test_by_person_table(db):
    ids = _seed_pilot(db)
    section = _section6a(_report(db))
    a, b = ids["A"], ids["B"]

    assert (
        "| person | arm | source | false_positive | benign | escalated | decisions | "
        "median acknowledge → decide | n (acknowledged in the window) |\n"
    ) in section
    for line in (
        f"| {a} | blind | lab | 2 | 1 | 1 | 4 | 1.50 min | 4 |",
        f"| {a} | blind | all | 2 | 1 | 1 | 4 | 1.50 min | 4 |",
        f"| {a} | visible | lab | 1 | 0 | 0 | 1 | 2.50 min | 1 |",
        f"| {b} | blind | wazuh | 2 | 1 | 1 | 4 | 1.75 min | 4 |",
        f"| {b} | visible | wazuh | 0 | 1 | 1 | 2 | 3.50 min | 2 |",
        f"| {b} | visible | all | 0 | 1 | 1 | 2 | 3.50 min | 2 |",
    ):
        assert line in section, line


@pytest.mark.db
def test_the_pilot_window_is_half_open_and_pairs_acknowledges_inside_it(db):
    a = _user(db)
    blind = {"source": "lab", "visible": False, "actor": a, "suggested": "false_positive"}
    # decided 1 s before the start: excluded
    _handled(db, ack_at=-61, took=60, outcome="false_positive", **blind)
    # decided at the start (inclusive), its acknowledge 30 s before it: counted, not timed
    _handled(db, ack_at=-30, took=30, outcome="false_positive", **blind)
    # inside, 60 s
    _handled(db, ack_at=60, took=60, outcome="false_positive", **blind)
    # decided 1 microsecond before the end (inclusive), 120 s
    end_offset = PILOT_END - PILOT_START
    _handled(
        db,
        ack_at=end_offset - TICK - timedelta(seconds=120),
        took=120,
        outcome="false_positive",
        **blind,
    )
    # decided exactly at the end (exclusive)
    _handled(
        db, ack_at=end_offset - timedelta(seconds=60), took=60, outcome="false_positive", **blind
    )

    section = _section6a(_report(db))

    assert "| blind | lab | 3 | 0 | 0 | 3 |" in section
    assert (
        "| blind | lab | 1.50 min | 2 | 3 |" in section
    )  # 60 s and 120 s; one not acknowledged in
    assert "| lab | 3 | 0 | 0 | 3 | 3 | 1.000 (3 / 3) |" in section


@pytest.mark.db
def test_an_end_left_out_is_the_database_clock(db):
    a = _user(db)
    _handled(
        db,
        source="lab",
        visible=False,
        actor=a,
        ack_at=60,
        took=60,
        outcome="benign",
        suggested="false_positive",
    )
    future = _open(db, received_at=at(10), source="lab", visible=False)
    _ack(db, future, a, datetime.now(UTC) + timedelta(hours=1))
    _close(db, future, a, datetime.now(UTC) + timedelta(hours=2), "closed_fp")

    text = _report(db, _pilot(end=None))
    section = _section6a(text)

    assert "the database clock at the run" in section
    assert "| blind | lab | 0 | 1 | 0 | 1 |" in section  # the decision two hours ahead is not in
    assert datetime.now(UTC).strftime("%Y-%m-%d") not in text  # no run timestamp in the file


@pytest.mark.db
def test_synthetic_alerts_are_not_pilot_decisions(db):
    a = _user(db)
    _handled(
        db,
        source="lab",
        visible=False,
        actor=a,
        ack_at=60,
        took=60,
        outcome="false_positive",
        suggested="false_positive",
        synthetic=True,
    )

    section = _section6a(_report(db))

    assert "| blind | all | 0 | 0 | 0 | 0 |" in section
    assert "| all | 0 | 0 | 0 | 0 | 0 | n/a (0 rows) |" in section


# --- without --pilot-start ----------------------------------------------------------------------


@pytest.mark.db
def test_without_a_pilot_start_the_section_says_not_measured(db):
    _seed_pilot(db)  # the decisions exist; without a start none of them is a pilot decision

    text = ops_export.build_report(db, _window())
    section = _section6a(text)

    assert NOT_MEASURED in section
    assert "| blind |" not in section and "| visible |" not in section
    assert not re.search(r"\bQ(29|3\d)\b", text)  # no pilot query ran, so none is cited
    assert len(_appendix_sql(text)) == len(ops_export.QUERIES)
    rows = _section_rows(text, "6 · ")
    for metric in (
        "Decisions by branch (blind / visible) and by person",
        "Median acknowledge → decide, by branch",
        "① agreement with human decisions, blind branch only",
    ):
        # the export window's own evidence (Q24, 10 `tier1.decided`) is counted beside the pointer
        assert rows[metric][0].startswith("descriptive, n = "), metric
        assert (
            "pass `--pilot-start` for the pilot's figures (section 6a)" in rows[metric][1]
        ), metric
        assert "measured over the pilot window" not in rows[metric][1], metric


def _section_rows(text: str, heading: str) -> dict[str, tuple[str, str]]:
    rows = {}
    for line in _section(text, heading).splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if line.startswith("| ") and len(cells) == 3 and cells[0] != "metric":
            rows[cells[0]] = (cells[1], cells[2])
    return rows


@pytest.mark.db
def test_section_six_points_at_the_pilot_figures_when_a_start_is_given(db):
    _seed_pilot(db)
    rows = _section_rows(_report(db), "6 · ")

    decisions = rows["Decisions by branch (blind / visible) and by person"]
    assert decisions[0] == "measured, n = 11"
    assert "section 6a" in decisions[1] and "Q29" in decisions[1]
    median = rows["Median acknowledge → decide, by branch"]
    assert median[0] == "measured, n = 11" and "Q30" in median[1]
    # n is what the fraction is over (the denominator, 5), not the blind decisions (8): those are
    # in the basis, beside it
    agreement = rows["① agreement with human decisions, blind branch only"]
    assert agreement[0] == "measured, n = 5" and "Q31" in agreement[1]
    assert "agreement denominator = 5" in agreement[1]
    assert "blind decisions = 8" in agreement[1]


@pytest.mark.db
def test_the_stale_reasons_are_replaced(db):
    text = ops_export.build_report(db, _window())
    rows = _section_rows(text, "6 · ")

    digest = rows["Auto-close wrong-close rate from the digest, with its Wilson CI"]
    assert "live since P5 (DEC-154)" in digest[1]
    usefulness = rows["② usefulness, 1–5"]
    assert usefulness[0] == "not measured: no rating control in v1.0 (DEC-161)"
    assert "built and run, no rating control in v1.0 (DEC-154, DEC-161)" in usefulness[1]
    section = _section(text, "6 · ")
    assert "DEC-116" not in section and "deprioritized" not in section
    assert "DEC-097" not in section and "DEC-111" not in section


# --- the SQL is the citation ----------------------------------------------------------------------


@pytest.mark.db
def test_every_pilot_query_is_printed_verbatim_in_section_8(db, monkeypatch):
    _seed_pilot(db)
    sent: list[str] = []
    real_execute = ops_export._execute

    def recording_execute(conn, sql, params):
        sent.append(sql)
        return real_execute(conn, sql, params)

    monkeypatch.setattr(ops_export, "_execute", recording_execute)
    text = _report(db)

    assert sent == [q.sql for q in (*ops_export.QUERIES, *ops_export.PILOT_QUERIES)]
    assert _appendix_sql(text) == sent
    ids = re.findall(r"^### (Q\d\d) · ", _section(text, "8 · "), flags=re.MULTILINE)
    assert ids == [f"Q{i:02d}" for i in range(1, len(ids) + 1)]
    assert {q.qid for q in ops_export.PILOT_QUERIES} == {"Q29", "Q30", "Q31", "Q32", "Q33"}
    body = text[: text.index("\n## 8 · ")]
    assert set(re.findall(r"\bQ\d\d\b", body)) <= set(ids)
    assert "`%(pilot_start)s`" in _section(text, "8 · ")


@pytest.mark.db
def test_the_pilot_output_is_byte_identical_and_holds_no_free_text(db):
    _seed_pilot(db)
    first = _report(db, _pilot(end=None))
    second = _report(db, _pilot(end=None))

    assert first == second
    assert MARKER not in first  # every payload's reason carries it; none reaches the file
    # not vacuous. With the end left out, X3's decision (blind, lab, benign, 5 h 3 min after the
    # start) is inside the window too: blind all = 4 false_positive, 3 benign, 2 escalated
    assert "| blind | all | 4 | 3 | 2 | 9 |" in first


@pytest.mark.db
def test_the_pilot_runs_in_the_read_only_session(_test_database):
    conn = ops_export._connect_readonly(_test_database)
    try:
        text = ops_export.build_report(conn, _window(), _pilot(end=None))
        assert "\n## 6a · " in text and "\n### Q33 · " in text
    finally:
        conn.rollback()
        conn.close()


# --- the command line -----------------------------------------------------------------------------


def test_parse_pilot_window():
    assert ops_export.parse_pilot(None, None) is None
    open_ended = ops_export.parse_pilot("2011-03-14T10:00:00Z", None)
    assert open_ended == ops_export.PilotWindow(PILOT_START, None)
    closed = ops_export.parse_pilot("2011-03-14T10:00:00Z", "2011-03-14T15:00:00+00:00")
    assert closed == ops_export.PilotWindow(PILOT_START, PILOT_END)
    for start, end in (
        ("2011-03-14T10:00:00Z", "2011-03-14T09:00:00Z"),  # inverted
        ("2011-03-14T10:00:00Z", "2011-03-14T10:00:00Z"),  # empty
        ("2011-03-14T10:00:00", None),  # naive
        ("2011-03-14T17:00:00+07:00", None),  # not UTC
        ("yesterday", None),
        (None, "2011-03-14T15:00:00Z"),  # an end without a start
    ):
        with pytest.raises(ops_export.Exit) as raised:
            ops_export.parse_pilot(start, end)
        assert raised.value.code == 2, (start, end)


@pytest.mark.db
def test_the_command_writes_the_pilot_section(db, monkeypatch, tmp_path):
    _seed_pilot(db)

    @contextmanager
    def _borrow(_dsn):
        yield db

    monkeypatch.setattr(ops_export, "_readonly_connection", _borrow)
    base = ["--since", "2011-03-14T00:00:00Z", "--until", "2011-03-15T00:00:00Z"]
    base += ["--dsn", UNUSED_DSN]

    with_pilot = tmp_path / "with.md"
    argv = [*base, "--pilot-start", "2011-03-14T10:00:00Z", "--pilot-end", "2011-03-14T15:00:00Z"]
    assert ops_export.main([*argv, "--out", str(with_pilot)]) == 0
    text = with_pilot.read_text(encoding="utf-8")
    assert "| blind | all | 4 | 2 | 2 | 8 |" in text
    assert "`%(pilot_end)s` = `2011-03-14T15:00:00Z`" in text

    without = tmp_path / "without.md"
    assert ops_export.main([*base, "--out", str(without)]) == 0
    assert NOT_MEASURED in without.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "extra",
    [
        ["--pilot-start", "not-a-date"],
        ["--pilot-start", "2026-10-01T00:00:00"],
        ["--pilot-start", "2026-10-02T00:00:00Z", "--pilot-end", "2026-10-01T00:00:00Z"],
        ["--pilot-end", "2026-10-01T00:00:00Z"],
    ],
)
def test_pilot_usage_errors_exit_2_before_any_connection(monkeypatch, tmp_path, capsys, extra):
    def _no(*_args, **_kwargs):
        raise AssertionError("a usage error must exit before any DSN is read or connected")

    monkeypatch.setattr(ops_export, "_resolve_dsn", _no)
    monkeypatch.setattr(ops_export, "_readonly_connection", _no)
    out = tmp_path / "o.md"
    argv = ["--until", "2026-10-07T00:00:00Z", *extra, "--dsn", UNUSED_DSN, "--out", str(out)]
    assert ops_export.main(argv) == 2
    assert not out.exists()
    assert capsys.readouterr().err.strip()


def test_help_names_the_pilot_flags():
    parser = ops_export.build_parser()
    assert parser.parse_args(["--until", "2026-10-07T00:00:00Z"]).pilot_start is None
    help_text = parser.format_help()
    assert "--pilot-start" in help_text and "--pilot-end" in help_text
    assert "--pilot-start" in ops_export.__doc__
