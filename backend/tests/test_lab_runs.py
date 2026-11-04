"""P14-T09 — `lab.runs`: recording a lab run, listing the runs, and finding the run a moment belongs to.

A run is a name, a purpose (`kb` builds the knowledge base, `test` is scored) and a half-open window
`[starts_at, ends_at)`. Two windows never overlap (the database says so); an alert belongs to the run whose
window holds its `received_at`. `create_run` writes one `lab.run_created` event with the run's id, name and
purpose, in the caller's transaction, and leaves that transaction usable when it refuses.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, timezone

import pytest
from app.lab import runs

from tests.lab_data import at, insert_run
from tests.scratch_db import insert_alert, insert_user
from tests.test_archive import _put_alert

pytestmark = pytest.mark.db


def _create(db, admin: str, **over) -> runs.LabRun:
    row = {"name": "Lần 1", "purpose": "test", "starts_at": at(0), "ends_at": at(2)}
    row.update(over)
    return runs.create_run(db, admin_id=admin, **row)


def _events(db, event_type: str) -> list[tuple]:
    return db.execute(
        "SELECT subject_id, actor_role, actor_id::text, payload FROM audit_events "
        "WHERE event_type = %s ORDER BY audit_id",
        (event_type,),
    ).fetchall()


# ── the shape ───────────────────────────────────────────────────────────────────────────────


def test_a_lab_run_has_exactly_the_five_fields_of_the_contract():
    assert [f.name for f in dataclasses.fields(runs.LabRun)] == [
        "run_id",
        "name",
        "purpose",
        "starts_at",
        "ends_at",
    ]
    assert runs.LabRun.__dataclass_params__.frozen


def test_the_purposes_are_kb_and_test():
    assert runs.PURPOSES == ("kb", "test")


def test_the_refusals_share_a_base_class():
    assert issubclass(runs.RunOverlap, runs.LabError)
    assert issubclass(runs.InvalidRun, runs.LabError)
    assert issubclass(runs.UnknownRun, runs.LabError)


# ── create_run ──────────────────────────────────────────────────────────────────────────────


def test_create_run_stores_the_run_and_returns_it(db):
    admin = insert_user(db, "admin")
    run = _create(db, admin, name="Lần 1", purpose="kb", starts_at=at(1), ends_at=at(3))
    assert isinstance(run, runs.LabRun)
    assert (run.name, run.purpose, run.starts_at, run.ends_at) == ("Lần 1", "kb", at(1), at(3))
    assert isinstance(run.run_id, str) and len(run.run_id) == 36
    stored = db.execute(
        "SELECT run_id::text, name, purpose, starts_at, ends_at, created_by::text "
        "FROM lab_runs WHERE run_id = %s",
        (run.run_id,),
    ).fetchone()
    assert stored == (run.run_id, "Lần 1", "kb", at(1), at(3), admin)


def test_create_run_writes_one_lab_run_created_event_for_the_admin(db):
    admin = insert_user(db, "admin")
    run = _create(db, admin, name="Lần 2", purpose="test")
    assert _events(db, "lab.run_created") == [
        (run.run_id, "admin", admin, {"run_id": run.run_id, "name": "Lần 2", "purpose": "test"})
    ]


def test_create_run_accepts_a_window_given_in_any_offset(db):
    admin = insert_user(db, "admin")
    plus7 = timezone(timedelta(hours=7))
    run = _create(
        db,
        admin,
        starts_at=datetime(2026, 11, 5, 16, 0, tzinfo=plus7),
        ends_at=datetime(2026, 11, 5, 18, 0, tzinfo=plus7),
    )
    assert run.starts_at == datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
    assert run.ends_at == datetime(2026, 11, 5, 11, 0, tzinfo=UTC)


def test_create_run_strips_the_name(db):
    admin = insert_user(db, "admin")
    assert _create(db, admin, name="  padded  ").name == "padded"


def test_two_runs_that_abut_are_both_recorded(db):
    admin = insert_user(db, "admin")
    first = _create(db, admin, name="a", starts_at=at(0), ends_at=at(2))
    second = _create(db, admin, name="b", starts_at=at(2), ends_at=at(4))
    assert first.run_id != second.run_id


# ── create_run refuses ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "first,second",
    [((0, 4), (2, 6)), ((2, 6), (0, 4)), ((0, 6), (2, 4)), ((2, 4), (0, 6)), ((0, 4), (0, 4))],
    ids=["starts-inside", "ends-inside", "inside", "holds", "same"],
)
def test_an_overlapping_run_is_refused_with_run_overlap(db, first, second):
    admin = insert_user(db, "admin")
    _create(db, admin, name="first", starts_at=at(first[0]), ends_at=at(first[1]))
    with pytest.raises(runs.RunOverlap):
        _create(db, admin, name="second", starts_at=at(second[0]), ends_at=at(second[1]))


def test_a_refused_run_leaves_no_row_no_event_and_a_usable_transaction(db):
    admin = insert_user(db, "admin")
    _create(db, admin, name="first", starts_at=at(0), ends_at=at(4))
    with pytest.raises(runs.RunOverlap):
        _create(db, admin, name="second", starts_at=at(1), ends_at=at(2))
    assert db.execute("SELECT count(*) FROM lab_runs").fetchone() == (1,)
    assert len(_events(db, "lab.run_created")) == 1
    # the transaction is not aborted: the next valid run goes in
    assert _create(db, admin, name="third", starts_at=at(5), ends_at=at(6)).name == "third"


@pytest.mark.parametrize("purpose", ["train", "KB", "", None, "kb ", 1])
def test_an_unknown_purpose_is_invalid(db, purpose):
    admin = insert_user(db, "admin")
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, admin, purpose=purpose)
    assert (caught.value.field, caught.value.reason) == ("purpose", "invalid")


@pytest.mark.parametrize("hours", [(2, 2), (2, 1), (5, 0)], ids=["equal", "before", "far-before"])
def test_an_end_that_is_not_after_the_start_is_invalid(db, hours):
    admin = insert_user(db, "admin")
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, admin, starts_at=at(hours[0]), ends_at=at(hours[1]))
    assert (caught.value.field, caught.value.reason) == ("ends_at", "not_after_starts")


@pytest.mark.parametrize("field", ["starts_at", "ends_at"])
@pytest.mark.parametrize(
    "value",
    [datetime(2026, 11, 5, 10, 0), "2026-11-05T10:00:00Z", None, 1762335600],  # noqa: DTZ001
    ids=["naive", "text", "none", "number"],
)
def test_a_time_that_is_not_a_timezone_aware_datetime_is_invalid(db, field, value):
    admin = insert_user(db, "admin")
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, admin, **{field: value})
    assert (caught.value.field, caught.value.reason) == (field, "invalid")


@pytest.mark.parametrize(
    "field,moment",
    [
        ("starts_at", datetime(1, 1, 1, 0, 0, tzinfo=timezone(timedelta(hours=14)))),
        ("ends_at", datetime(9999, 12, 31, 23, 0, tzinfo=timezone(timedelta(hours=-14)))),
    ],
    ids=["before-year-1-in-utc", "after-year-9999-in-utc"],
)
def test_a_time_that_has_no_utc_form_is_invalid_not_an_overflow(db, field, moment):
    over = {field: moment}
    over["ends_at" if field == "starts_at" else "starts_at"] = at(4 if field == "starts_at" else 0)
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, insert_user(db, "admin"), **over)
    assert (caught.value.field, caught.value.reason) == (field, "invalid")


def test_a_time_is_normalised_to_utc():
    moment = runs._check_time(
        "starts_at", datetime(2026, 11, 5, 16, 0, tzinfo=timezone(timedelta(hours=7)))
    )
    assert moment == datetime(2026, 11, 5, 9, 0, tzinfo=UTC)
    assert moment.utcoffset() == timedelta(0)


@pytest.mark.parametrize("name", ["", "   ", "\t\n"])
def test_an_empty_name_is_invalid(db, name):
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, insert_user(db, "admin"), name=name)
    assert (caught.value.field, caught.value.reason) == ("name", "empty")


def test_a_name_over_eighty_characters_is_invalid(db):
    admin = insert_user(db, "admin")
    assert _create(db, admin, name="x" * 80).name == "x" * 80
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, admin, name="y" * 81, starts_at=at(5), ends_at=at(6))
    assert (caught.value.field, caught.value.reason) == ("name", "too_long")


@pytest.mark.parametrize(
    "name",
    [
        "a\x00b",
        "a\nb",
        "a" + chr(0x202E) + "b",
        "a" + chr(0x200B) + "b",
        "a" + chr(0x2028) + "b",
        "a" + chr(0xD800) + "b",
        7,
        None,
    ],
    ids=["nul", "newline", "bidi", "zero-width", "line-sep", "surrogate", "int", "none"],
)
def test_a_name_with_a_control_or_invisible_character_or_that_is_not_text_is_invalid(db, name):
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, insert_user(db, "admin"), name=name)
    assert (caught.value.field, caught.value.reason) == ("name", "invalid")


def test_a_name_already_taken_is_invalid_and_leaves_the_transaction_usable(db):
    admin = insert_user(db, "admin")
    _create(db, admin, name="same", starts_at=at(0), ends_at=at(1))
    with pytest.raises(runs.InvalidRun) as caught:
        _create(db, admin, name="same", starts_at=at(5), ends_at=at(6))
    assert (caught.value.field, caught.value.reason) == ("name", "taken")
    assert len(_events(db, "lab.run_created")) == 1
    _create(db, admin, name="other", starts_at=at(5), ends_at=at(6))


def test_nothing_is_written_when_the_input_is_refused_before_the_database(db):
    admin = insert_user(db, "admin")
    with pytest.raises(runs.InvalidRun):
        _create(db, admin, purpose="nope")
    assert db.execute("SELECT count(*) FROM lab_runs").fetchone() == (0,)
    assert _events(db, "lab.run_created") == []


# ── list_runs, get_run ──────────────────────────────────────────────────────────────────────


def test_list_runs_is_empty_when_there_is_none(db):
    assert runs.list_runs(db) == []


def test_list_runs_gives_every_run_newest_window_first(db):
    admin = insert_user(db, "admin")
    old = _create(db, admin, name="old", starts_at=at(0), ends_at=at(1))
    new = _create(db, admin, name="new", starts_at=at(10), ends_at=at(12))
    mid = _create(db, admin, name="mid", starts_at=at(5), ends_at=at(6))
    assert runs.list_runs(db) == [new, mid, old]


def test_get_run_returns_the_run_or_none(db):
    admin = insert_user(db, "admin")
    run = _create(db, admin)
    assert runs.get_run(db, run.run_id) == run
    assert runs.get_run(db, "00000000-0000-4000-8000-000000000000") is None


# ── run_of ──────────────────────────────────────────────────────────────────────────────────


def test_run_of_finds_the_run_whose_window_holds_the_moment(db):
    admin = insert_user(db, "admin")
    first = _create(db, admin, name="first", starts_at=at(0), ends_at=at(2))
    second = _create(db, admin, name="second", starts_at=at(4), ends_at=at(6))
    assert runs.run_of(db, at(1)) == first
    assert runs.run_of(db, at(5)) == second


def test_the_window_is_closed_at_its_start_and_open_at_its_end(db):
    admin = insert_user(db, "admin")
    run = _create(db, admin, starts_at=at(1), ends_at=at(3))
    assert runs.run_of(db, at(1)) == run
    assert runs.run_of(db, at(3) - timedelta(microseconds=1)) == run
    assert runs.run_of(db, at(3)) is None
    assert runs.run_of(db, at(1) - timedelta(microseconds=1)) is None


def test_the_end_of_one_run_is_the_start_of_the_next(db):
    admin = insert_user(db, "admin")
    first = _create(db, admin, name="first", starts_at=at(0), ends_at=at(2))
    second = _create(db, admin, name="second", starts_at=at(2), ends_at=at(4))
    assert runs.run_of(db, at(2)) == second
    assert runs.run_of(db, at(2) - timedelta(microseconds=1)) == first


def test_run_of_is_none_before_between_and_after_the_runs(db):
    admin = insert_user(db, "admin")
    _create(db, admin, name="first", starts_at=at(2), ends_at=at(3))
    _create(db, admin, name="second", starts_at=at(5), ends_at=at(6))
    for hours in (0, 4, 8):
        assert runs.run_of(db, at(hours)) is None


def test_run_of_with_no_run_at_all_is_none(db):
    assert runs.run_of(db, at(0)) is None


# ── the counts a run is listed with ─────────────────────────────────────────────────────────


def test_run_counts_are_the_queue_heads_in_the_window_and_the_labelled_among_them(db):
    admin = insert_user(db, "admin")
    run = _create(db, admin, starts_at=at(0), ends_at=at(4))
    head_a = _put_alert(db, "c-a", received_at=at(1))
    _put_alert(db, "c-b", received_at=at(2))
    _put_alert(db, "c-c", received_at=at(3.5))
    # a duplicate under a head is not a queue head: not counted
    _put_alert(db, "c-dup", status="duplicate", duplicate_of=head_a, received_at=at(1.5))
    # outside the window: not counted
    _put_alert(db, "c-before", received_at=at(-1))
    _put_alert(db, "c-after", received_at=at(4))
    for alert_id in ("c-a", "c-b"):
        db.execute(
            "INSERT INTO lab_labels (alert_id, run_id, label, labeled_by) VALUES (%s, %s, %s, %s)",
            (alert_id, run.run_id, "true_positive", admin),
        )
    assert runs.run_counts(db, run) == runs.RunCounts(total=3, labelled=2)


def test_run_counts_of_an_empty_window_are_zero(db):
    run = _create(db, insert_user(db, "admin"))
    insert_alert(db, "c-now")
    assert runs.run_counts(db, run) == runs.RunCounts(total=0, labelled=0)


def test_a_label_on_a_duplicate_is_not_counted_as_labelled(db):
    admin = insert_user(db, "admin")
    run = _create(db, admin, starts_at=at(0), ends_at=at(4))
    head = _put_alert(db, "d-head", received_at=at(1))
    _put_alert(db, "d-dup", status="duplicate", duplicate_of=head, received_at=at(2))
    db.execute(
        "INSERT INTO lab_labels (alert_id, run_id, label, labeled_by) VALUES ('d-dup', %s, "
        "'false_positive', %s)",
        (run.run_id, admin),
    )
    assert runs.run_counts(db, run) == runs.RunCounts(total=1, labelled=0)


def test_insert_run_helper_agrees_with_create_run(db):
    admin = insert_user(db, "admin")
    run_id = insert_run(db, admin, start=0, end=2)
    assert runs.run_of(db, at(1)).run_id == run_id
