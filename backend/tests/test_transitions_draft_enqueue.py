"""P13-T04 / DEC-210, spec §7.3 — `transitions.decide` and `transitions.conclude_case` enqueue the
`knowledge_draft` job, in the same transaction as the conclusion, when `KNOWLEDGE_DRAFT_ENABLED`.

* the subject is `alert:<id>` (the alert an analyst decided) or `case:<uuid>` (the case concluded, once,
  not once per alert);
* with the switch off (its default) nothing is enqueued and the conclusion is what it was;
* `escalate` never enqueues one: an escalation is not a conclusion;
* the job lives and dies with the conclusion's transaction: a refused conclusion, or a conclusion
  rolled back by its caller, leaves no job.

`domain` may import only `infra` and `audit` (`test_import_rules.py`), so the two functions spell the
subject themselves; the test pins that the spelling is `rag.subject`'s.

Every test runs inside the `db` fixture's transaction and is rolled back.
"""

from __future__ import annotations

import uuid

import pytest
from app.domain import transitions
from app.rag.subject import Subject, parse_subject

from tests.rag_data import add_alert, add_case, add_user

pytestmark = pytest.mark.db


class _Abort(Exception):
    """Raised inside a savepoint to roll it back, as a caller whose later step fails would."""


@pytest.fixture
def switch_on(monkeypatch) -> None:
    monkeypatch.setenv("KNOWLEDGE_DRAFT_ENABLED", "true")


def draft_jobs(db) -> list[tuple[str, str, str]]:
    return db.execute(
        "SELECT job_type, subject_id, status FROM jobs WHERE job_type = 'knowledge_draft'"
        " ORDER BY job_id"
    ).fetchall()


def active_alert(db, alert_id: str = "te-1", **kwargs) -> tuple[str, str]:
    """An alert a Tier-1 analyst holds, and that analyst."""
    user = add_user(db)
    add_alert(db, alert_id, **kwargs)
    transitions.acknowledge(db, alert_id, user)
    return alert_id, user


def decide(db, alert_id: str, user: str, decision: str = "closed_fp", **kwargs) -> None:
    transitions.decide(
        db,
        alert_id,
        user,
        decision=decision,
        reason="p13t04",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
        **kwargs,
    )


def open_case(db, heads: tuple[str, ...] = ("tc-1",)) -> tuple[str, str]:
    user = add_user(db)
    for head in heads:
        add_alert(db, head)
    return add_case(db, user, heads), user


# ── decide ────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("decision", ["closed_fp", "closed_benign"])
def test_decide_enqueues_the_draft_for_the_alert(db, switch_on, decision) -> None:
    alert_id, user = active_alert(db)
    decide(db, alert_id, user, decision)
    assert draft_jobs(db) == [("knowledge_draft", "alert:te-1", "pending")]


def test_the_subject_is_the_one_the_job_parses(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    decide(db, alert_id, user)
    ((_, subject_id, _),) = draft_jobs(db)
    assert subject_id == Subject("alert", alert_id).key
    assert parse_subject(subject_id) == Subject("alert", alert_id)


def test_decide_enqueues_nothing_with_the_switch_off(db) -> None:
    alert_id, user = active_alert(db)
    decide(db, alert_id, user)
    assert draft_jobs(db) == []
    assert (
        db.execute("SELECT status FROM alerts WHERE alert_id = 'te-1'").fetchone()[0] == "closed_fp"
    )


@pytest.mark.parametrize("value", ["false", "0", ""])
def test_the_switch_is_off_for_any_false_value(db, monkeypatch, value) -> None:
    monkeypatch.setenv("KNOWLEDGE_DRAFT_ENABLED", value)
    alert_id, user = active_alert(db)
    decide(db, alert_id, user)
    assert draft_jobs(db) == []


def test_decide_enqueues_one_job_for_a_cluster_not_one_per_duplicate(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    add_alert(db, "te-dup-1", duplicate_of=alert_id, status="duplicate")
    add_alert(db, "te-dup-2", duplicate_of=alert_id, status="duplicate")
    decide(db, alert_id, user)
    assert draft_jobs(db) == [("knowledge_draft", "alert:te-1", "pending")]


def test_the_job_is_written_in_the_conclusions_own_transaction(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    with (
        pytest.raises(_Abort),
        db.transaction(),
    ):  # a savepoint: what the caller's later failure undoes
        decide(db, alert_id, user)
        assert len(draft_jobs(db)) == 1  # inside the same transaction it is there
        raise _Abort
    assert draft_jobs(db) == []
    assert (
        db.execute("SELECT status FROM alerts WHERE alert_id = 'te-1'").fetchone()[0]
        == "tier1_active"
    )


def test_a_refused_decision_enqueues_nothing(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    decide(db, alert_id, user)
    db.execute("DELETE FROM jobs")  # the first decision's job, so the second refusal is measurable
    with pytest.raises(transitions.StaleState):
        decide(db, alert_id, user)  # already closed
    with pytest.raises(transitions.StaleState):
        decide(db, "te-missing", user)
    assert draft_jobs(db) == []


def test_a_decision_on_a_stale_occurrence_count_enqueues_nothing(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    db.execute("UPDATE alerts SET occurrence_count = 50 WHERE alert_id = %s", (alert_id,))
    with pytest.raises(transitions.StaleState):
        decide(db, alert_id, user)
    assert draft_jobs(db) == []


def test_an_illegal_decision_enqueues_nothing(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    with pytest.raises(transitions.IllegalTransition):
        decide(db, alert_id, user, "escalate")
    assert draft_jobs(db) == []


# ── conclude_case ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "conclusion", ["concluded_fp", "concluded_policy_violation", "confirmed_incident"]
)
def test_conclude_case_enqueues_the_draft_for_the_case(db, switch_on, conclusion) -> None:
    case_id, user = open_case(db)
    transitions.conclude_case(db, case_id, user, conclusion=conclusion, reason="p13t04")
    assert draft_jobs(db) == [("knowledge_draft", f"case:{case_id}", "pending")]
    assert parse_subject(f"case:{case_id}") == Subject("case", case_id)


def test_a_case_is_drafted_once_not_once_per_alert(db, switch_on) -> None:
    case_id, user = open_case(db, heads=("tc-1", "tc-2", "tc-3"))
    add_alert(db, "tc-dup", duplicate_of="tc-1", status="duplicate")
    transitions.conclude_case(db, case_id, user, conclusion="concluded_fp", reason="p13t04")
    assert draft_jobs(db) == [("knowledge_draft", f"case:{case_id}", "pending")]


def test_a_case_id_is_queued_in_the_spelling_the_job_parses(db, switch_on) -> None:
    case_id, user = open_case(db)
    transitions.conclude_case(db, case_id.upper(), user, conclusion="concluded_fp", reason="p13t04")
    ((_, subject_id, _),) = draft_jobs(db)
    assert subject_id == Subject("case", case_id).key  # lower case, as `parse_subject` reads it


def test_conclude_case_enqueues_nothing_with_the_switch_off(db) -> None:
    case_id, user = open_case(db)
    transitions.conclude_case(db, case_id, user, conclusion="concluded_fp", reason="p13t04")
    assert draft_jobs(db) == []
    assert db.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()[0] == (
        "concluded_fp"
    )


def test_the_case_job_is_written_in_the_conclusions_own_transaction(db, switch_on) -> None:
    case_id, user = open_case(db)
    with pytest.raises(_Abort), db.transaction():
        transitions.conclude_case(db, case_id, user, conclusion="concluded_fp", reason="p13t04")
        assert len(draft_jobs(db)) == 1
        raise _Abort
    assert draft_jobs(db) == []
    status = db.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()[0]
    assert status == "investigating"


def test_a_refused_conclusion_enqueues_nothing(db, switch_on) -> None:
    case_id, user = open_case(db)
    transitions.conclude_case(db, case_id, user, conclusion="concluded_fp", reason="p13t04")
    db.execute("DELETE FROM jobs")
    with pytest.raises(transitions.StaleState):
        transitions.conclude_case(
            db, case_id, user, conclusion="confirmed_incident", reason="again"
        )
    with pytest.raises(transitions.StaleState):
        transitions.conclude_case(
            db, str(uuid.uuid4()), user, conclusion="concluded_fp", reason="x"
        )
    with pytest.raises(transitions.IllegalTransition):
        transitions.conclude_case(db, case_id, user, conclusion="needs_review", reason="x")  # type: ignore[arg-type]
    assert draft_jobs(db) == []


# ── escalate ──────────────────────────────────────────────────────────────────────────────────


def test_escalate_never_enqueues_a_draft(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    case_id = transitions.escalate(db, alert_id, user, title="p13t04", severity="medium")
    assert case_id
    assert draft_jobs(db) == []
    assert db.execute("SELECT status FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[
        0
    ] == ("escalated_tier2")


def test_escalate_then_conclude_enqueues_exactly_the_conclusion(db, switch_on) -> None:
    alert_id, user = active_alert(db)
    case_id = transitions.escalate(db, alert_id, user, title="p13t04", severity="medium")
    assert draft_jobs(db) == []
    transitions.conclude_case(db, case_id, user, conclusion="concluded_fp", reason="p13t04")
    assert draft_jobs(db) == [("knowledge_draft", f"case:{case_id}", "pending")]
