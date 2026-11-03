"""P14-T09 — `lab.labels`: an admin's hand label on an alert, and the blind list of a run's alerts.

* `set_label` finds the run from the alert's `received_at`, stores the label (one per alert), and writes one
  `lab.labeled {alert_id, run_id, label}` event for the admin each time it is called; an alert that does not
  exist is `UnknownAlert`, one received outside every window is `OutsideEveryRun`, a label other than
  `true_positive | false_positive` is `InvalidLabel`.
* `clear_label` removes the label and writes the same event with `label: null`; clearing what is not there
  is a no-op with no event.
* `run_alerts` lists a run's queue heads (received inside the window, `duplicate_of IS NULL`), oldest
  first, each as `tier1.visibility.strip(..., mode="labeling")` plus `label`: no key of ①, whatever the arm
  the alert is on (DEC-101).
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

import pytest
from app.lab import labels
from app.lab import runs as lab_runs
from app.tier1 import visibility
from psycopg.types.json import Jsonb

from tests.lab_data import at, insert_run
from tests.scratch_db import insert_user
from tests.test_archive import _put_alert

pytestmark = pytest.mark.db

#: The keys the brief names, and then everything else a labeller must never receive.
BRIEF_KEYS = ("suggested_action", "proposed_action", "held_by", "rag")


def _events(db, subject: str | None = None) -> list[tuple]:
    query = (
        "SELECT subject_id, actor_role, actor_id::text, payload FROM audit_events "
        "WHERE event_type = 'lab.labeled'"
    )
    params: tuple = ()
    if subject is not None:
        query += " AND subject_id = %s"
        params = (subject,)
    return db.execute(query + " ORDER BY audit_id", params).fetchall()


def _label_row(db, alert_id: str) -> tuple | None:
    return db.execute(
        "SELECT run_id::text, label, labeled_by::text FROM lab_labels WHERE alert_id = %s",
        (alert_id,),
    ).fetchone()


def _world(db):
    admin = insert_user(db, "admin")
    run = insert_run(db, admin, start=0, end=4)
    return admin, run


def _keys(value: Any) -> set[str]:
    """Every dict key at any depth."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            found |= _keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            found |= _keys(item)
    return found


# ── set_label ───────────────────────────────────────────────────────────────────────────────


def test_the_labels_are_true_positive_and_false_positive():
    assert labels.LABELS == ("true_positive", "false_positive")


def test_set_label_stores_the_label_and_returns_the_run_id(db):
    admin, run = _world(db)
    _put_alert(db, "l-1", received_at=at(1))
    assert labels.set_label(db, "l-1", "true_positive", admin) == run
    assert _label_row(db, "l-1") == (run, "true_positive", admin)


def test_set_label_writes_one_lab_labeled_event_for_the_admin(db):
    admin, run = _world(db)
    _put_alert(db, "l-2", received_at=at(1))
    labels.set_label(db, "l-2", "false_positive", admin)
    assert _events(db, "l-2") == [
        (
            "l-2",
            "admin",
            admin,
            {"alert_id": "l-2", "run_id": run, "label": "false_positive"},
        )
    ]


def test_the_run_is_derived_from_received_at_not_chosen(db):
    admin = insert_user(db, "admin")
    first = insert_run(db, admin, start=0, end=2)
    second = insert_run(db, admin, start=2, end=4)
    _put_alert(db, "l-3", received_at=at(1))
    _put_alert(db, "l-4", received_at=at(2))  # the start of the second window is its own
    assert labels.set_label(db, "l-3", "true_positive", admin) == first
    assert labels.set_label(db, "l-4", "false_positive", admin) == second


def test_an_alert_received_at_the_end_of_a_window_is_outside_it(db):
    admin, _ = _world(db)
    _put_alert(db, "l-5", received_at=at(4))
    with pytest.raises(labels.OutsideEveryRun):
        labels.set_label(db, "l-5", "true_positive", admin)


@pytest.mark.parametrize(
    "hours", [-5, -0.001, 4, 9], ids=["well-before", "just-before", "end", "after"]
)
def test_an_alert_outside_every_window_is_refused_and_nothing_is_written(db, hours):
    admin, _ = _world(db)
    _put_alert(db, "l-6", received_at=at(hours))
    with pytest.raises(labels.OutsideEveryRun):
        labels.set_label(db, "l-6", "true_positive", admin)
    assert _label_row(db, "l-6") is None
    assert _events(db) == []


def test_an_alert_in_the_gap_between_two_runs_is_outside_every_run(db):
    admin = insert_user(db, "admin")
    insert_run(db, admin, start=0, end=2)
    insert_run(db, admin, start=3, end=5)
    _put_alert(db, "l-7", received_at=at(2.5))
    with pytest.raises(labels.OutsideEveryRun):
        labels.set_label(db, "l-7", "true_positive", admin)


def test_with_no_run_at_all_every_alert_is_outside(db):
    admin = insert_user(db, "admin")
    _put_alert(db, "l-8", received_at=at(1))
    with pytest.raises(labels.OutsideEveryRun):
        labels.set_label(db, "l-8", "true_positive", admin)


def test_an_unknown_alert_is_refused_and_nothing_is_written(db):
    admin, _ = _world(db)
    with pytest.raises(labels.UnknownAlert):
        labels.set_label(db, "no-such-alert", "true_positive", admin)
    assert _events(db) == []


@pytest.mark.parametrize(
    "label",
    ["benign", "escalate", "TP", "fp", "True_Positive", "", " true_positive", None, 1, True],
)
def test_a_label_outside_the_two_is_refused_and_nothing_is_written(db, label):
    admin, _ = _world(db)
    _put_alert(db, "l-9", received_at=at(1))
    with pytest.raises(labels.InvalidLabel):
        labels.set_label(db, "l-9", label, admin)
    assert _label_row(db, "l-9") is None
    assert _events(db) == []


def test_the_label_is_checked_before_the_alert_is_looked_up(db):
    """A bad label on an unknown alert is the label's refusal: it is the request that is malformed."""
    admin, _ = _world(db)
    with pytest.raises(labels.InvalidLabel):
        labels.set_label(db, "no-such-alert", "benign", admin)


def test_every_refusal_is_a_lab_error():
    for error in (labels.UnknownAlert, labels.OutsideEveryRun, labels.InvalidLabel):
        assert issubclass(error, lab_runs.LabError)


def test_a_refusal_leaves_the_transaction_usable(db):
    admin, _ = _world(db)
    with pytest.raises(labels.UnknownAlert):
        labels.set_label(db, "nope", "true_positive", admin)
    _put_alert(db, "l-10", received_at=at(1))
    labels.set_label(db, "l-10", "true_positive", admin)


# ── relabelling ─────────────────────────────────────────────────────────────────────────────


def test_relabelling_changes_the_label_and_writes_one_event_more(db):
    admin, run = _world(db)
    _put_alert(db, "r-1", received_at=at(1))
    labels.set_label(db, "r-1", "true_positive", admin)
    assert labels.set_label(db, "r-1", "false_positive", admin) == run
    assert _label_row(db, "r-1") == (run, "false_positive", admin)
    assert db.execute("SELECT count(*) FROM lab_labels WHERE alert_id = 'r-1'").fetchone() == (1,)
    assert [e[3]["label"] for e in _events(db, "r-1")] == ["true_positive", "false_positive"]


def test_relabelling_by_another_admin_records_the_new_admin(db):
    first, run = _world(db)
    second = insert_user(db, "admin")
    _put_alert(db, "r-2", received_at=at(1))
    labels.set_label(db, "r-2", "true_positive", first)
    labels.set_label(db, "r-2", "true_positive", second)
    assert _label_row(db, "r-2") == (run, "true_positive", second)
    assert [e[2] for e in _events(db, "r-2")] == [first, second]


def test_relabelling_moves_labeled_at_forward(db):
    admin, _ = _world(db)
    _put_alert(db, "r-3", received_at=at(1))
    labels.set_label(db, "r-3", "true_positive", admin)
    db.execute("UPDATE lab_labels SET labeled_at = now() - interval '1 day' WHERE alert_id = 'r-3'")
    labels.set_label(db, "r-3", "false_positive", admin)
    age = db.execute(
        "SELECT now() - labeled_at < interval '1 minute' FROM lab_labels WHERE alert_id = 'r-3'"
    ).fetchone()
    assert age == (True,)


# ── clear_label ─────────────────────────────────────────────────────────────────────────────


def test_clearing_a_label_removes_it_and_writes_the_event_with_a_null_label(db):
    admin, run = _world(db)
    _put_alert(db, "c-1", received_at=at(1))
    labels.set_label(db, "c-1", "true_positive", admin)
    assert labels.clear_label(db, "c-1", admin) is None
    assert _label_row(db, "c-1") is None
    events = _events(db, "c-1")
    assert [e[3] for e in events] == [
        {"alert_id": "c-1", "run_id": run, "label": "true_positive"},
        {"alert_id": "c-1", "run_id": run, "label": None},
    ]
    assert events[1][:3] == ("c-1", "admin", admin)


def test_clearing_what_is_not_there_is_a_no_op_with_no_event(db):
    admin, _ = _world(db)
    _put_alert(db, "c-2", received_at=at(1))
    assert labels.clear_label(db, "c-2", admin) is None
    assert labels.clear_label(db, "never-existed", admin) is None
    assert _events(db) == []


def test_a_cleared_alert_can_be_labelled_again(db):
    admin, run = _world(db)
    _put_alert(db, "c-3", received_at=at(1))
    labels.set_label(db, "c-3", "true_positive", admin)
    labels.clear_label(db, "c-3", admin)
    assert labels.set_label(db, "c-3", "false_positive", admin) == run
    assert len(_events(db, "c-3")) == 3


# ── run_alerts ──────────────────────────────────────────────────────────────────────────────


def test_a_runs_alerts_are_only_those_received_inside_its_window(db):
    admin = insert_user(db, "admin")
    run = insert_run(db, admin, start=2, end=4)
    other = insert_run(db, admin, start=5, end=6)
    for alert_id, hours in [
        ("w-before", 1.999),
        ("w-start", 2),
        ("w-mid", 3),
        ("w-last", 3.999),
        ("w-end", 4),
        ("w-gap", 4.5),
        ("w-other", 5.5),
    ]:
        _put_alert(db, alert_id, received_at=at(hours))
    assert [a["alert_id"] for a in labels.run_alerts(db, run)] == ["w-start", "w-mid", "w-last"]
    assert [a["alert_id"] for a in labels.run_alerts(db, other)] == ["w-other"]


def test_a_runs_alerts_are_queue_heads_only(db):
    admin, run = _world(db)
    head = _put_alert(db, "h-head", received_at=at(1))
    _put_alert(db, "h-dup1", status="duplicate", duplicate_of=head, received_at=at(1.1))
    _put_alert(db, "h-dup2", status="duplicate", duplicate_of=head, received_at=at(1.2))
    _put_alert(db, "h-other", status="closed_fp", received_at=at(2), acknowledged_by=admin)
    assert [a["alert_id"] for a in labels.run_alerts(db, run)] == ["h-head", "h-other"]


def test_the_alerts_come_oldest_first_then_by_id(db):
    _admin, run = _world(db)
    _put_alert(db, "o-c", received_at=at(2))
    _put_alert(db, "o-b", received_at=at(1))
    _put_alert(db, "o-z", received_at=at(1))
    _put_alert(db, "o-a", received_at=at(3))
    assert [a["alert_id"] for a in labels.run_alerts(db, run)] == ["o-b", "o-z", "o-c", "o-a"]


def test_after_and_limit_page_through_the_alerts_without_a_gap_or_a_repeat(db):
    _admin, run = _world(db)
    ids = [f"p-{i:02d}" for i in range(7)]
    for i, alert_id in enumerate(ids):
        _put_alert(db, alert_id, received_at=at(0.1 * i))
    seen: list[str] = []
    after = None
    for _ in range(10):
        page = labels.run_alerts(db, run, after=after, limit=3)
        assert len(page) <= 3
        if not page:
            break
        seen += [a["alert_id"] for a in page]
        after = page[-1]["alert_id"]
    assert seen == ids


def test_after_walks_the_same_moment_in_id_order(db):
    _admin, run = _world(db)
    for alert_id in ("same-c", "same-a", "same-b"):
        _put_alert(db, alert_id, received_at=at(1))
    page = labels.run_alerts(db, run, after="same-a", limit=10)
    assert [a["alert_id"] for a in page] == ["same-b", "same-c"]


def test_after_an_unknown_alert_gives_nothing(db):
    _admin, run = _world(db)
    _put_alert(db, "u-1", received_at=at(1))
    assert labels.run_alerts(db, run, after="never-existed") == []


def test_the_default_limit_is_one_hundred(db):
    _admin, run = _world(db)
    for i in range(103):
        _put_alert(db, f"d-{i:03d}", received_at=at(0) + timedelta(seconds=i))
    assert len(labels.run_alerts(db, run)) == 100
    assert len(labels.run_alerts(db, run, after="d-099")) == 3


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, None, "10", labels.MAX_LIMIT + 1])
def test_a_limit_that_is_not_a_whole_number_from_one_to_the_maximum_is_refused(db, limit):
    _admin, run = _world(db)
    with pytest.raises(ValueError):
        labels.run_alerts(db, run, limit=limit)


def test_an_unknown_run_is_refused(db):
    with pytest.raises(lab_runs.UnknownRun):
        labels.run_alerts(db, str(uuid.uuid4()))


def test_each_alert_carries_its_label_or_none(db):
    admin, run = _world(db)
    for alert_id, hours in (("lab-a", 1), ("lab-b", 2), ("lab-c", 3)):
        _put_alert(db, alert_id, received_at=at(hours))
    labels.set_label(db, "lab-a", "true_positive", admin)
    labels.set_label(db, "lab-c", "false_positive", admin)
    assert [(a["alert_id"], a["label"]) for a in labels.run_alerts(db, run)] == [
        ("lab-a", "true_positive"),
        ("lab-b", None),
        ("lab-c", "false_positive"),
    ]


def test_the_item_is_the_alert_the_labeller_needs_and_nothing_more(db):
    _admin, run = _world(db)
    _put_alert(db, "k-1", received_at=at(1))
    (item,) = labels.run_alerts(db, run)
    assert set(item) == set(labels.ITEM_KEYS) | {"label"}
    assert item["alert_id"] == "k-1"
    assert item["received_at"] == at(1)
    assert item["raw_log"] == "log k-1" and item["raw_log_truncated_for_display"] is False


def test_an_item_is_what_strip_in_labeling_mode_returns_plus_the_label(db):
    _admin, run = _world(db)
    _put_alert(db, "s-1", received_at=at(1))
    (item,) = labels.run_alerts(db, run)
    bare = {k: v for k, v in item.items() if k != "label"}
    assert (
        visibility.strip(bare, status="queued_tier1", suggestion_visible=True, mode="labeling")
        == bare
    )
    assert (
        visibility.strip(bare, status="closed_fp", suggestion_visible=False, mode="labeling")
        == bare
    )


def _put_everything_of_one(db, alert_id: str, admin: str, hours: float, *, visible: bool) -> None:
    """An alert that ① has answered and the pipeline has enriched: a triage run with a verdict, a held
    reason in its gate result, a lookup, a SOAR blob in the payload, a risk score and a case."""
    _put_alert(db, alert_id, received_at=at(hours), suggestion_visible=visible, triaged_count=2)
    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, gate_result) VALUES (%s, 'triage', 'alert', %s, 's', 'u', %s, %s)",
        (
            str(uuid.uuid4()),
            alert_id,
            Jsonb({"suggested_action": "needs_review", "marker": "LLM-RESULT-MARKER"}),
            Jsonb(
                {"held_by": ["step2"], "proposed_action": "true_positive", "marker": "GATE-MARKER"}
            ),
        ),
    )
    db.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, matches) "
        "VALUES (gen_random_uuid(), 'alert', %s, 'ok', %s)",
        (alert_id, Jsonb([{"entry_id": "e1", "marker": "RAG-MARKER"}])),
    )
    db.execute(
        "UPDATE alerts SET raw_payload = %s, risk_score = 77 WHERE alert_id = %s",
        (Jsonb({"soar": {"triage_score": 91, "marker": "SOAR-MARKER"}}), alert_id),
    )


@pytest.mark.parametrize("visible", [True, False], ids=["visible-arm", "blind-arm"])
def test_no_item_carries_a_key_of_one_whatever_the_arm(db, visible):
    admin, run = _world(db)
    _put_everything_of_one(db, "b-1", admin, 1, visible=visible)
    _put_everything_of_one(db, "b-2", admin, 2, visible=visible)
    items = labels.run_alerts(db, run)
    assert len(items) == 2
    found = set().union(*(_keys(item) for item in items))
    for key in BRIEF_KEYS:
        assert key not in found, key
    assert found.isdisjoint(visibility.LABELING_DENYLIST)
    assert not any(key.startswith(visibility.LABELING_PREFIXES) for key in found)
    dumped = json.dumps(items, default=str)
    for marker in ("LLM-RESULT-MARKER", "GATE-MARKER", "RAG-MARKER", "SOAR-MARKER", "needs_review"):
        assert marker not in dumped, marker


def test_the_status_the_arm_and_the_triage_state_are_not_in_an_item(db):
    admin, run = _world(db)
    _put_everything_of_one(db, "n-1", admin, 1, visible=False)
    (item,) = labels.run_alerts(db, run)
    for key in (
        "status",
        "suggestion_visible",
        "triage_status",
        "triaged_count",
        "risk_score",
        "risk_band",
        "case_id",
        "duplicate_of",
        "source",
        "soar",
    ):
        assert key not in item, key


def test_a_long_raw_log_is_cut_for_display_and_says_so(db):
    _admin, run = _world(db)
    _put_alert(db, "x-1", received_at=at(1))
    db.execute("UPDATE alerts SET raw_log = repeat('a', 200000) WHERE alert_id = 'x-1'")
    (item,) = labels.run_alerts(db, run)
    assert item["raw_log_truncated_for_display"] is True
    assert 0 < len(item["raw_log"].encode()) <= labels.RAW_LOG_DISPLAY_BYTES


def test_a_raw_log_of_multibyte_characters_is_cut_on_a_character_boundary(db):
    _admin, run = _world(db)
    _put_alert(db, "x-2", received_at=at(1))
    db.execute("UPDATE alerts SET raw_log = repeat('é', 100000) WHERE alert_id = 'x-2'")
    (item,) = labels.run_alerts(db, run)
    assert item["raw_log_truncated_for_display"] is True
    assert len(item["raw_log"].encode()) <= labels.RAW_LOG_DISPLAY_BYTES
    assert set(item["raw_log"]) == {"é"}


def test_a_log_over_the_byte_cap_but_under_the_character_cap_is_cut_and_says_so(db):
    """20 000 two-byte characters: under the 32 768 characters the database cuts to, over 32 768 bytes."""
    _admin, run = _world(db)
    _put_alert(db, "x-3", received_at=at(1))
    db.execute("UPDATE alerts SET raw_log = repeat('é', 20000) WHERE alert_id = 'x-3'")
    (item,) = labels.run_alerts(db, run)
    assert item["raw_log_truncated_for_display"] is True
    assert len(item["raw_log"].encode()) <= labels.RAW_LOG_DISPLAY_BYTES


def test_a_log_at_the_byte_cap_is_shown_whole(db):
    _admin, run = _world(db)
    _put_alert(db, "x-4", received_at=at(1))
    db.execute("UPDATE alerts SET raw_log = repeat('a', 32768) WHERE alert_id = 'x-4'")
    (item,) = labels.run_alerts(db, run)
    assert item["raw_log_truncated_for_display"] is False
    assert len(item["raw_log"]) == 32768


def test_the_raw_log_cap_is_the_gold_pages():
    from app.tier1 import labels as gold

    assert labels.RAW_LOG_DISPLAY_BYTES == gold.RAW_LOG_DISPLAY_BYTES
