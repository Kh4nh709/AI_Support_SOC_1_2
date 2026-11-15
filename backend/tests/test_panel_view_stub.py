"""DEC-221, card AP-T1 - the existing Tier 2 page keeps working on a version 4 run. PURE: no database, no socket.

`tier2/investigation_view.py` serves `next_steps` as a list of strings, as the page reads it: each row's `step` for
a version 4 run, the strings themselves for a version 3 one; the keys it does not know (`timeline`, `scope`,
`likelihood`) change nothing of what it served. (The other readers of a stored answer - the dossier and the
knowledge drafter - are in `test_panel_readers.py`.)
"""

from __future__ import annotations

import copy
import datetime as dt
import uuid

from app.tier2 import investigation_view

from tests.fakes.llm import INVESTIGATE_V3_OK, INVESTIGATE_V4_OK

CREATED = dt.datetime(2026, 11, 15, 9, 30, tzinfo=dt.UTC)


# --------------------------------------------------------------------------- the Tier 2 view


def _row(result: dict, check: dict | None = None) -> tuple:
    """A row of `investigation_view._RUN_COLUMNS`: run_id, created_at, stopped_by, result, evidence_check,
    agent_trace, citation_warnings, the lookup's `matches` and (DEC-220) its `ranked`."""
    return (uuid.uuid4(), CREATED, None, result, check or {}, None, None, None, None)


#: What AP-T3 added to a run of the view (`test_panel_t2_pure.py` pins it): the existing page reads none of it.
AP_T3_KEYS = ("timeline", "scope", "next_steps_rows", "evidence_summary", "tech")


def _as_served(result: dict) -> dict:
    """The run as the page that existed before DEC-221 reads it: without the keys of AP-T3 and without a
    hypothesis's `likelihood`."""
    served = investigation_view.present_run(_row(result))
    kept = {k: v for k, v in served.items() if k not in ("result", "run_id", *AP_T3_KEYS)}
    kept["hypotheses"] = [
        {k: v for k, v in hypothesis.items() if k != "likelihood"}
        for hypothesis in kept["hypotheses"]
    ]
    return kept


def test_the_view_serves_next_steps_as_strings_for_a_version_3_run():
    assert investigation_view.present_run(_row(INVESTIGATE_V3_OK))["next_steps"] == [
        "Rotate credentials for user1.",
        "Review sshd logs for the source IP over the prior 7 days.",
    ]


def test_the_view_serves_next_steps_as_each_rows_step_for_a_version_4_run():
    assert investigation_view.present_run(_row(INVESTIGATE_V4_OK))["next_steps"] == [
        "Rotate credentials for user1.",
        "Review sshd logs for the source IP over the prior 7 days.",
    ]


def test_the_view_of_a_version_4_run_is_the_view_of_its_version_3_form():
    """Everything the page reads: the conclusion, the summary, the narrative, the hypotheses (without the
    `likelihood` the page does not know), the evidence rows, the steps. The keys it does not know change nothing.
    The whole view of a run now carries AP-T3's keys beside them (the card's own tests pin those; here they are
    taken out of both sides).
    """
    assert _as_served(INVESTIGATE_V4_OK) == _as_served(INVESTIGATE_V3_OK)
    served = investigation_view.present_run(_row(INVESTIGATE_V4_OK))
    assert set(served["hypotheses"][0]) == {
        "text",
        "evidence_for",
        "evidence_against",
        "likelihood",
    }


def test_the_view_of_a_run_with_odd_next_steps_does_not_fail():
    odd = {**copy.deepcopy(INVESTIGATE_V4_OK), "next_steps": [None, 3, {"x": 1}, {"step": "ok"}]}
    # a step with no text is dropped; an item that is not a row is left as it always was
    assert investigation_view.present_run(_row(odd))["next_steps"] == [None, 3, "ok"]
    missing = {k: v for k, v in INVESTIGATE_V4_OK.items() if k != "next_steps"}
    assert investigation_view.present_run(_row(missing))["next_steps"] == []
