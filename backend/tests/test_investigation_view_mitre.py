"""DEC-223, Task 3 - what the ② view serves of a timeline's `technique` once the local ATT&CK reference can check it
(spec 7, G5). PURE: no database, no socket; the facts of the case's alerts come in as a `CaseAlerts`.

`timeline[].technique` is free text from the model. Each served row gains two keys, whatever
`PROMPT_INCLUDE_MITRE_REFERENCE` says (they describe what the model returned, not what it was shown):

* `technique_name`: MITRE's own name for the id, when the value names an id the reference holds;
* `technique_known`: `True` for such an id, `False` for a value shaped like an ATT&CK id that the reference does
  not hold (a sub-technique found only through its parent is one: the model named an id MITRE does not have), and
  `None` for anything else (empty, null, prose, a number) and when there is no reference file.

The run also carries `checks.technique_not_in_reference`, the number of served rows with `technique_known: False`
(`None` without a reference). Nothing the model stored is rewritten: the row keeps its own `technique`, and the
raw `result` serves the stored shape.
"""

from __future__ import annotations

import copy

import pytest
from app.kb import mitre
from app.tier2 import investigation_view as view

from tests.test_panel_t2_pure import _alerts, _row, _t, _v4
from tests.test_triage_prompt_mitre import use_extract


@pytest.fixture(autouse=True)
def _fresh_reference():
    mitre.reset_cache()
    yield
    mitre.reset_cache()


def served(*techniques, alerts=None, **over) -> dict:
    """A run whose timeline has one row per technique value, each on an alert of the case."""
    rows = [
        {"alert_id": f"a-{i}", "what": f"step {i}", "tactic": "Execution", "technique": technique}
        for i, technique in enumerate(techniques)
    ]
    times = {row["alert_id"]: _t(i) for i, row in enumerate(rows)}
    return view.present_run(_row(_v4(timeline=rows, **over)), None, alerts or _alerts(times))


def pair(row: dict) -> tuple:
    return row["technique_name"], row["technique_known"]


def test_a_known_id_is_served_with_the_references_own_name() -> None:
    run = served("T1110.001")
    assert pair(run["timeline"][0]) == ("Password Guessing", True)
    assert run["timeline"][0]["technique"] == "T1110.001"
    assert run["checks"] == {"technique_not_in_reference": 0}


def test_a_parent_technique_and_a_revoked_one_are_known_with_their_own_names() -> None:
    run = served("T1110", "T1086")
    assert [pair(r) for r in run["timeline"]] == [("Brute Force", True), ("PowerShell", True)]


def test_an_id_the_reference_does_not_hold_is_marked_and_counted() -> None:
    run = served("T9999", "T1110", "T9998")
    assert [pair(r) for r in run["timeline"]] == [
        (None, False),
        ("Brute Force", True),
        (None, False),
    ]
    assert run["checks"] == {"technique_not_in_reference": 2}
    assert [r["technique"] for r in run["timeline"]] == [
        "T9999",
        "T1110",
        "T9998",
    ]  # what the model said


def test_a_sub_technique_the_reference_does_not_hold_is_not_known_through_its_parent() -> None:
    run = served("T1059.999")
    assert pair(run["timeline"][0]) == (None, False)  # the model named an id MITRE does not have
    assert run["checks"] == {"technique_not_in_reference": 1}


@pytest.mark.parametrize("spelled", ["t1110.001", " T1110.001 ", "T1110.001\t", "t1110.001 "])
def test_the_case_and_surrounding_white_space_of_an_id_do_not_matter(spelled: str) -> None:
    run = served(spelled)
    assert pair(run["timeline"][0]) == ("Password Guessing", True)
    assert run["timeline"][0]["technique"] == spelled  # nothing the model stored is rewritten


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        None,
        "brute force",
        "Password Guessing",
        "T1110.001 - Password Guessing",
        "T1110, T1078",
        "T11",
        "T1110.1",
        "T1110.00x",
        "T١١١١",
        "<b>T1110</b>",
        7,
        ["T1110"],
        {"id": "T1110"},
    ],
)
def test_an_empty_null_or_prose_value_is_served_as_today_with_no_name_and_no_verdict(value) -> None:
    run = served(value)
    row = run["timeline"][0]
    assert pair(row) == (None, None)
    assert row["technique"] == (value if isinstance(value, str) and value.strip() else None)
    assert run["checks"] == {"technique_not_in_reference": 0}


def test_a_row_keeps_every_key_it_had_and_gains_the_two_in_this_order() -> None:
    run = served("T1110")
    assert list(run["timeline"][0]) == [
        "alert_id",
        "time",
        "what",
        "tactic",
        "technique",
        "technique_name",
        "technique_known",
    ]


def test_the_raw_result_keeps_the_stored_shape_and_gains_nothing() -> None:
    run = served("T1110", "T9999")
    assert [list(row) for row in run["result"]["timeline"]] == [
        ["alert_id", "what", "tactic", "technique"]
    ] * 2
    assert view.TIMELINE_KEYS == ("alert_id", "what", "tactic", "technique")


def test_a_missing_reference_is_no_verdict_and_no_error(monkeypatch, tmp_path) -> None:
    use_extract(monkeypatch, tmp_path / "absent.json")
    run = served("T1110.001", "T9999", "brute force")
    assert [pair(r) for r in run["timeline"]] == [(None, None)] * 3
    assert run["checks"] == {"technique_not_in_reference": None}
    assert [r["technique"] for r in run["timeline"]] == ["T1110.001", "T9999", "brute force"]


def test_a_damaged_reference_is_the_same(monkeypatch, tmp_path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("[1, 2", encoding="utf-8")
    use_extract(monkeypatch, broken)
    run = served("T1110.001")
    assert pair(run["timeline"][0]) == (None, None)
    assert run["checks"] == {"technique_not_in_reference": None}


def test_the_switch_does_not_change_what_is_served(monkeypatch) -> None:
    rows = [
        {"alert_id": f"a-{i}", "what": "w", "tactic": "", "technique": technique}
        for i, technique in enumerate(["T1110.001", "T9999", "x"])
    ]
    row = _row(_v4(timeline=rows))  # one stored row, read twice
    alerts = _alerts({r["alert_id"]: _t(i) for i, r in enumerate(rows)})
    monkeypatch.setenv("PROMPT_INCLUDE_MITRE_REFERENCE", "false")
    off = view.present_run(row, None, alerts)
    monkeypatch.setenv("PROMPT_INCLUDE_MITRE_REFERENCE", "true")
    on = view.present_run(row, None, alerts)
    assert off == on
    assert [pair(r) for r in on["timeline"]] == [
        ("Password Guessing", True),
        (None, False),
        (None, None),
    ]


def test_only_the_served_rows_are_checked_and_counted() -> None:
    """A row naming an alert outside the case is dropped before it is read: its technique is nobody's."""
    rows = [
        {"alert_id": "a-1", "what": "mine", "tactic": "", "technique": "T1110"},
        {"alert_id": "not-mine", "what": "foreign", "tactic": "", "technique": "T9999"},
    ]
    run = view.present_run(_row(_v4(timeline=rows)), None, _alerts({"a-1": _t(1)}))
    assert [pair(r) for r in run["timeline"]] == [("Brute Force", True)]
    assert run["checks"] == {"technique_not_in_reference": 0}


def test_the_count_is_of_rows_not_of_distinct_ids() -> None:
    assert served("T9999", "T9999", "T9999")["checks"] == {"technique_not_in_reference": 3}


def test_a_run_with_no_timeline_checks_nothing() -> None:
    result = copy.deepcopy(_v4())
    result.pop("timeline")
    run = view.present_run(_row(result), None, _alerts({}))
    assert run["timeline"] == []
    assert run["checks"] == {"technique_not_in_reference": 0}


def test_a_run_that_stopped_with_no_result_has_no_checks() -> None:
    run = view.present_run(_row(None), None, None)
    assert "checks" not in run and "timeline" not in run
