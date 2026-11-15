"""DEC-221, card AP-T3 - what the Tier 2 case view serves of a run's new fields. PURE: no database, no socket (the
database half, through the route, is `test_panel_t2_db.py`).

The view is `tier2.investigation_view.present_run`; the facts it takes from the case's own alerts come in as a
`CaseAlerts` (the one read `case_alerts` makes), so everything here is a function of a stored row and that value.

* the timeline: a row's `time` is the `alert_time` of the alert it names, never the model's; a row naming an alert
  outside the case is dropped; sorted by time, ties by the stored order; capped at `TIMELINE_CAP`;
* `scope`: the model's `{hosts, accounts}` beside what the system knows, `{system: {hosts, accounts, alert_count}}`;
* a hypothesis's `likelihood`, `next_steps_rows`, `evidence_summary`, `tech` (no model id: goal G5);
* the raw `result` carries the filtered timeline in its stored shape and is otherwise the stored result;
* an older run (version 2 or 3) and a garbled document give less, never an error.
"""

from __future__ import annotations

import ast
import copy
import datetime as dt
import json
import pathlib
import uuid

import pytest
from app.llm import results
from app.llm.builder import rag_not_applied_warning
from app.rag.failures import FAILURE_KINDS
from app.tier2 import investigation_view as view

from tests.fakes.llm import INVESTIGATE_V3_OK, INVESTIGATE_V4_OK

CREATED = dt.datetime(2026, 11, 15, 9, 30, tzinfo=dt.UTC)
T0 = dt.datetime(2026, 11, 15, 8, 0, tzinfo=dt.UTC)


def _t(minutes: int) -> dt.datetime:
    return T0 + dt.timedelta(minutes=minutes)


def _row(
    result,
    check=None,
    *,
    usage=(1200, 340, 5400, 0.00123),
    trace=None,
    warnings=None,
    matches=None,
    ranked=None,
) -> tuple:
    """A row of `investigation_view._RUN_COLUMNS`: run_id, created_at, stopped_by, result, evidence_check, agent_trace,
    citation_warnings, the lookup's `matches` and `ranked`, then the four figures of the run (input tokens, output
    tokens, latency, cost)."""
    return (
        uuid.uuid4(),
        CREATED,
        None,
        result,
        check or {},
        trace,
        warnings,
        matches,
        ranked,
        *usage,
    )


def _alerts(times: dict[str, dt.datetime], **kw) -> view.CaseAlerts:
    base = {"alert_count": len(times), "hosts": ("host-a",), "accounts": ("user1",)}
    return view.CaseAlerts(**{**base, **kw}, times=times)


def _rows(*pairs: tuple[str, str]) -> list[dict]:
    """Timeline rows `(alert_id, what)` in the stored shape."""
    return [
        {"alert_id": alert_id, "what": what, "tactic": "Execution", "technique": None}
        for alert_id, what in pairs
    ]


def _v4(**over) -> dict:
    return {**copy.deepcopy(INVESTIGATE_V4_OK), **over}


def _served(result, alerts=None, **kw) -> dict:
    return view.present_run(_row(result, **kw), None, alerts)


# --------------------------------------------------------------------------- the timeline


def test_a_rows_time_is_the_time_of_the_alert_it_names():
    times = {"a-1": _t(5), "a-2": _t(1)}
    served = _served(_v4(timeline=_rows(("a-1", "first"), ("a-2", "second"))), _alerts(times))
    assert served["timeline"] == [
        {
            "alert_id": "a-2",
            "time": _t(1),
            "what": "second",
            "tactic": "Execution",
            "technique": None,
        },
        {
            "alert_id": "a-1",
            "time": _t(5),
            "what": "first",
            "tactic": "Execution",
            "technique": None,
        },
    ]
    assert list(served["timeline"][0]) == ["alert_id", "time", "what", "tactic", "technique"]


def test_a_row_naming_an_alert_outside_the_case_is_dropped():
    times = {"a-1": _t(1)}
    served = _served(_v4(timeline=_rows(("a-1", "mine"), ("not-mine", "foreign"))), _alerts(times))
    assert [r["alert_id"] for r in served["timeline"]] == ["a-1"]


def test_the_model_cannot_write_a_clock():
    """A stored row that carries a `time` of its own gets the alert's, not its own."""
    row = {**_rows(("a-1", "x"))[0], "time": "1999-01-01T00:00:00Z"}
    served = _served(_v4(timeline=[row]), _alerts({"a-1": _t(3)}))
    assert served["timeline"][0]["time"] == _t(3)


def test_rows_are_sorted_by_time_and_ties_keep_the_stored_order():
    times = {"a-1": _t(9), "a-2": _t(2), "a-3": _t(2), "a-4": _t(2), "a-5": _t(0)}
    stored = _rows(("a-1", "1"), ("a-3", "3"), ("a-2", "2"), ("a-4", "4"), ("a-5", "5"))
    served = _served(_v4(timeline=stored), _alerts(times))
    assert [r["what"] for r in served["timeline"]] == ["5", "3", "2", "4", "1"]


def test_two_rows_may_name_the_same_alert():
    served = _served(_v4(timeline=_rows(("a-1", "x"), ("a-1", "y"))), _alerts({"a-1": _t(1)}))
    assert [r["what"] for r in served["timeline"]] == ["x", "y"]


def test_the_list_is_capped_and_the_cap_is_fifty():
    assert view.TIMELINE_CAP == 50
    times = {f"a-{n}": _t(n) for n in range(view.TIMELINE_CAP + 10)}
    # stored in reverse: the cap keeps the earliest rows by time, not the first stored
    stored = _rows(*[(f"a-{n}", str(n)) for n in reversed(range(view.TIMELINE_CAP + 10))])
    served = _served(_v4(timeline=stored), _alerts(times))
    assert len(served["timeline"]) == view.TIMELINE_CAP
    assert [r["what"] for r in served["timeline"]] == [str(n) for n in range(view.TIMELINE_CAP)]
    assert len(served["result"]["timeline"]) == view.TIMELINE_CAP


def test_empty_tactic_and_technique_are_none_and_text_stays_text():
    stored = [
        {"alert_id": "a-1", "what": "x", "tactic": "", "technique": None},
        {"alert_id": "a-2", "what": "y", "tactic": "Persistence", "technique": "T1053"},
        {"alert_id": "a-3", "what": "z", "tactic": 7, "technique": "  "},
    ]
    times = {"a-1": _t(1), "a-2": _t(2), "a-3": _t(3)}
    rows = _served(_v4(timeline=stored), _alerts(times))["timeline"]
    assert [(r["tactic"], r["technique"]) for r in rows] == [
        (None, None),
        ("Persistence", "T1053"),
        (None, None),
    ]


def test_a_version_4_run_with_the_fake_answer_gets_its_time():
    alert_id = INVESTIGATE_V4_OK["timeline"][0]["alert_id"]
    served = _served(copy.deepcopy(INVESTIGATE_V4_OK), _alerts({alert_id: _t(4)}))
    assert served["timeline"][0]["time"] == _t(4)
    assert served["timeline"][0]["what"] == INVESTIGATE_V4_OK["timeline"][0]["what"]


# --------------------------------------------------------------------------- the raw result


def test_the_raw_result_carries_the_filtered_timeline_in_its_stored_shape():
    stored = _rows(("a-2", "late"), ("outside", "foreign"), ("a-1", "early"))
    result = _v4(timeline=stored)
    original = copy.deepcopy(result)
    served = _served(result, _alerts({"a-1": _t(1), "a-2": _t(9)}))
    assert served["result"]["timeline"] == [
        stored[2],
        stored[0],
    ]  # the stored rows, no `time`, same order as the view
    assert all("time" not in row for row in served["result"]["timeline"])
    assert result == original  # the stored document is not changed in place


def test_the_raw_result_is_otherwise_the_stored_result():
    result = _v4(timeline=_rows(("outside", "foreign")))
    served = _served(result, _alerts({}))
    assert served["result"] == {**result, "timeline": []}


def test_a_result_with_no_timeline_key_is_served_as_stored():
    result = copy.deepcopy(INVESTIGATE_V3_OK)
    assert "timeline" not in result
    assert _served(result, _alerts({}))["result"] == result


def test_a_garbled_timeline_in_the_raw_result_is_an_empty_list():
    assert _served(_v4(timeline="soon"), _alerts({}))["result"]["timeline"] == []
    assert _served(_v4(timeline={"a": 1}), _alerts({}))["result"]["timeline"] == []
    assert _served(_v4(timeline=None), _alerts({}))["result"]["timeline"] == []


# --------------------------------------------------------------------------- an older run, a garbled one


def test_a_version_3_run_gives_empty_new_fields_and_no_error():
    served = _served(copy.deepcopy(INVESTIGATE_V3_OK), _alerts({}, alert_count=2))
    assert served["timeline"] == []
    assert served["scope"] == {
        "hosts": [],
        "accounts": [],
        "system": {"hosts": ["host-a"], "accounts": ["user1"], "alert_count": 2},
    }
    assert [h["likelihood"] for h in served["hypotheses"]] == [None]
    assert served["next_steps_rows"] == [
        {"step": text, "priority": None} for text in INVESTIGATE_V3_OK["next_steps"]
    ]
    assert served["next_steps"] == INVESTIGATE_V3_OK["next_steps"]


def test_a_version_4_run_gives_its_likelihood_priority_and_scope():
    served = _served(copy.deepcopy(INVESTIGATE_V4_OK), _alerts({}))
    assert [h["likelihood"] for h in served["hypotheses"]] == ["high"]
    assert served["next_steps_rows"] == INVESTIGATE_V4_OK["next_steps"]
    assert served["scope"]["hosts"] == ["host-a"]
    assert served["scope"]["accounts"] == ["user1"]


def test_the_existing_keys_of_a_hypothesis_keep_their_values():
    served = _served(copy.deepcopy(INVESTIGATE_V4_OK), _alerts({}))
    h4 = INVESTIGATE_V4_OK["gia_thuyet"][0]
    assert served["hypotheses"] == [
        {
            "text": h4["noi_dung"],
            "evidence_for": h4["evidence_for"],
            "evidence_against": h4["evidence_against"],
            "likelihood": "high",
        }
    ]


@pytest.mark.parametrize("value", ["certain", "HIGH", 3, None, ["high"], {"a": 1}, True])
def test_a_likelihood_outside_the_closed_values_is_none(value):
    result = _v4()
    result["gia_thuyet"][0]["likelihood"] = value
    assert _served(result, _alerts({}))["hypotheses"][0]["likelihood"] is None


@pytest.mark.parametrize("value", ["low", "medium", "high"])
def test_every_closed_likelihood_passes_through(value):
    result = _v4()
    result["gia_thuyet"][0]["likelihood"] = value
    assert _served(result, _alerts({}))["hypotheses"][0]["likelihood"] == value


def test_next_steps_rows_priorities_are_closed_and_odd_items_are_dropped():
    steps = [
        {"step": "a", "priority": "high"},
        {"step": "b", "priority": "urgent"},
        {"step": "c"},
        {"priority": "low"},
        {"step": 3, "priority": "low"},
        "d",
        None,
        7,
    ]
    served = _served(_v4(next_steps=steps), _alerts({}))
    assert served["next_steps_rows"] == [
        {"step": "a", "priority": "high"},
        {"step": "b", "priority": None},
        {"step": "c", "priority": None},
        {"step": "d", "priority": None},
    ]
    # the list of strings is exactly what it was before this card (a pinned behaviour of the page)
    assert served["next_steps"] == ["a", "b", "c", "d", None, 7]


def test_next_steps_of_a_version_4_run_stay_the_strings_of_their_rows():
    served = _served(copy.deepcopy(INVESTIGATE_V4_OK), _alerts({}))
    assert served["next_steps"] == [row["step"] for row in INVESTIGATE_V4_OK["next_steps"]]


@pytest.mark.parametrize(
    "scope", [None, "host-a", ["host-a"], 3, {}, {"hosts": "h", "accounts": 3}]
)
def test_a_garbled_scope_gives_two_empty_lists(scope):
    served = _served(_v4(scope=scope), _alerts({}))
    assert served["scope"]["hosts"] == []
    assert served["scope"]["accounts"] == []


def test_scope_lists_keep_their_strings_and_drop_the_rest():
    served = _served(
        _v4(scope={"hosts": ["h1", 2, None, "h2"], "accounts": ["u", {"a": 1}]}), _alerts({})
    )
    assert served["scope"]["hosts"] == ["h1", "h2"]
    assert served["scope"]["accounts"] == ["u"]


def test_the_models_scope_is_capped():
    hosts = [f"h{n}" for n in range(view.SCOPE_CAP + 5)]
    served = _served(_v4(scope={"hosts": hosts, "accounts": []}), _alerts({}))
    assert served["scope"]["hosts"] == hosts[: view.SCOPE_CAP]


@pytest.mark.parametrize(
    "timeline",
    [
        None,
        "x",
        3,
        [None, 3, "x", [], {}],
        [{"alert_id": 5, "what": "x"}],
        [{"alert_id": "a-1"}],
        [{"alert_id": "a-1", "what": None}],
        [{"alert_id": ["a-1"], "what": "x"}],
        [{"what": "x"}],
    ],
)
def test_a_garbled_timeline_gives_an_empty_list_and_no_error(timeline):
    served = _served(_v4(timeline=timeline), _alerts({"a-1": _t(1)}))
    assert served["timeline"] == []


def test_a_garbled_result_never_raises():
    garbled = {
        "summary": None,
        "gia_thuyet": ["x", None, {"noi_dung": 3, "likelihood": 5}],
        "evidence": "x",
        "next_steps": {"a": 1},
        "timeline": [{"alert_id": "a-1", "what": "x", "tactic": [], "technique": {}}],
        "scope": [1, 2],
    }
    served = _served(garbled, _alerts({"a-1": _t(1)}))
    assert served["timeline"][0]["tactic"] is None
    assert served["next_steps_rows"] == []
    assert served["evidence_summary"] == {"cited": 0, "verified": 0}
    json.dumps(served, default=str)


# --------------------------------------------------------------------------- what the system knows


def test_scope_carries_what_the_system_knows_beside_the_models_words():
    alerts = _alerts({}, alert_count=7, hosts=("h1", "h2"), accounts=("root",))
    scope = _served(_v4(scope={"hosts": ["model-host"], "accounts": []}), alerts)["scope"]
    assert scope == {
        "hosts": ["model-host"],
        "accounts": [],
        "system": {"hosts": ["h1", "h2"], "accounts": ["root"], "alert_count": 7},
    }


def test_the_systems_lists_are_capped_too():
    hosts = tuple(f"h{n:03d}" for n in range(view.SCOPE_CAP + 5))
    system = _served(_v4(), _alerts({}, hosts=hosts))["scope"]["system"]
    assert system["hosts"] == list(hosts[: view.SCOPE_CAP])


def test_without_the_cases_alerts_the_system_part_is_empty_not_missing():
    scope = view.present_run(_row(_v4()))["scope"]
    assert scope["system"] == {"hosts": [], "accounts": [], "alert_count": 0}
    assert view.present_run(_row(_v4()))["timeline"] == []


# --------------------------------------------------------------------------- the tile and the technical tab


def test_evidence_summary_counts_cited_and_verified_from_the_rows_the_view_builds():
    evidence = [{"alert_id": "a-1", "quote": f"quote number {n}", "why": "w"} for n in range(4)]
    check = {"verified": [0, 2], "rejected": [{"index": 1, "reason": "quote_not_found"}]}
    served = _served(_v4(evidence=evidence), _alerts({}), check=check)
    assert served["evidence_summary"] == {"cited": 4, "verified": 2}
    assert sum(row["verified"] for row in served["evidence"]) == 2


def test_evidence_summary_with_no_check_verifies_nothing():
    evidence = [{"alert_id": "a-1", "quote": "a quote long enough", "why": "w"}]
    served = _served(_v4(evidence=evidence), _alerts({}), check={})
    assert served["evidence_summary"] == {"cited": 1, "verified": 0}


def test_tech_has_exactly_the_figures_of_the_run_and_no_model_id():
    trace = {"alert_count": 3, "total_occurrences": 20, "last_seen_at": None}
    served = _served(_v4(playbook_used="brute_force"), _alerts({}), trace=trace)
    assert served["tech"] == {
        "input_tokens": 1200,
        "output_tokens": 340,
        "latency_ms": 5400,
        "cost_usd": 0.00123,
        "analysed_at": CREATED,
        "playbook": "brute_force",
        "alerts_read": 3,
    }


def test_tech_of_a_row_without_figures_is_none_not_an_error():
    served = view.present_run(
        _row(_v4())[:9], None, _alerts({})
    )  # the nine columns that came first
    assert served["tech"] == {
        "input_tokens": None,
        "output_tokens": None,
        "latency_ms": None,
        "cost_usd": None,
        "analysed_at": CREATED,
        "playbook": INVESTIGATE_V4_OK["playbook_used"],
        "alerts_read": None,
    }


def test_tech_figures_are_numbers_or_none():
    import decimal

    served = _served(_v4(), _alerts({}), usage=("many", True, 1.5, decimal.Decimal("0.01234")))
    tech = served["tech"]
    assert tech["input_tokens"] is None
    assert tech["output_tokens"] is None  # a bool is not a count
    assert tech["latency_ms"] is None
    assert tech["cost_usd"] == 0.01234 and isinstance(tech["cost_usd"], float)
    assert json.dumps(tech, default=str)


# --------------------------------------------------------------------------- what a run without a result keeps


def test_a_run_without_a_result_carries_none_of_the_new_keys():
    row = (uuid.uuid4(), CREATED, "schema", None, None, None, None, None, None, 10, 5, 100, 0.001)
    served = view.present_run(row, None, _alerts({"a-1": _t(1)}))
    assert set(served) == {"run_id", "created_at", "rag", "result", "stopped_text"}
    assert served["result"] is None


def test_the_new_keys_of_a_run_with_a_result():
    served = _served(copy.deepcopy(INVESTIGATE_V4_OK), _alerts({}))
    assert {
        "timeline",
        "scope",
        "next_steps_rows",
        "evidence_summary",
        "tech",
    } <= set(served)


# --------------------------------------------------------------------------- the overrule is served as it was


def test_the_override_of_the_conclusion_is_served_as_it_always_was():
    """A conclusion the system changed to `need_more_data`: the sentence, the model's own answer, the held reasons and
    the unverified rows come out the same for a version 4 run and for its version 3 twin."""
    check = {
        "verified": [],
        "rejected": [{"index": 0, "reason": "quote_not_found"}],
        "model_conclusion": "false_positive",
        "original_conclusion": "false_positive",
    }
    v3 = {**copy.deepcopy(INVESTIGATE_V3_OK), "suggested_conclusion": "need_more_data"}
    v4 = {**copy.deepcopy(INVESTIGATE_V4_OK), "suggested_conclusion": "need_more_data"}
    old, new = _served(v3, _alerts({}), check=check), _served(v4, _alerts({}), check=check)
    for key in (
        "conclusion",
        "conclusion_label",
        "overruled",
        "model_conclusion",
        "held_by",
        "evidence",
    ):
        assert new[key] == old[key], key
    assert new["held_by"] == ["no_verified_evidence"]
    assert new["overruled"] is not None
    assert [row["verified"] for row in new["evidence"]] == [False]


# --------------------------------------------------------------------------- the readers


def test_the_readers_of_the_new_fields_are_where_the_stored_shapes_are_read():
    assert results.next_step_rows(["a", {"step": "b", "priority": "low"}]) == [
        {"step": "a", "priority": None},
        {"step": "b", "priority": "low"},
    ]
    assert results.level("medium") == "medium"
    assert results.level("MEDIUM") is None
    assert results.scope_lists({"hosts": ["h"], "accounts": None}) == {
        "hosts": ["h"],
        "accounts": [],
    }
    assert [row["what"] for row in results.timeline_entries(_rows(("a", "x"), ("b", "y")))] == [
        "x",
        "y",
    ]
    assert results.timeline_alert_ids(_rows(("a", "x"), ("b", "y"), ("a", "z"))) == ["a", "b"]
    assert results.timeline_alert_ids("x") == []


# --------------------------------------------------------------------------- the raw timeline's four keys


def test_a_raw_timeline_row_carries_only_the_four_known_keys():
    """A hand-edited stored row cannot carry a `time` of its own, or anything else, out through the raw result."""
    row = {
        "alert_id": "a-1",
        "what": "x",
        "tactic": "t",
        "technique": "T1",
        "time": "1999-01-01T00:00:00Z",
        "note": "<b>x</b>",
        "model": "zz-model",
    }
    served = _served(_v4(timeline=[row]), _alerts({"a-1": _t(3)}))
    assert served["result"]["timeline"] == [
        {"alert_id": "a-1", "what": "x", "tactic": "t", "technique": "T1"}
    ]
    assert served["timeline"][0]["time"] == _t(3)  # and the view's own row has the alert's time


def test_a_raw_timeline_row_keeps_the_known_keys_it_has_and_invents_none():
    row = {"alert_id": "a-1", "what": "x", "extra": 1}
    served = _served(_v4(timeline=[row]), _alerts({"a-1": _t(3)}))
    assert served["result"]["timeline"] == [{"alert_id": "a-1", "what": "x"}]
    assert served["timeline"][0]["tactic"] is None and served["timeline"][0]["technique"] is None


# --------------------------------------------------------------------------- the knowledge candidates (A)

E1, E2, E3, E4 = "entry-1", "entry-2", "entry-3", "entry-4"
CARDS = {
    E1: ("Quy tắc một", "confirmed_incident"),
    E2: ("Quy tắc hai", "false_positive"),
    E3: (None, "closed_fp"),
}
KNOWLEDGE_KEYS = {
    "state",
    "failure",
    "best_pct",
    "floor_pct",
    "threshold_pct",
    "scored",
    "candidates",
}


def _m(entry_id: str, score: float) -> dict:
    return {"entry_id": entry_id, "level": "giong", "content_sha256": "0" * 64, "score": score}


def _r(entry_id: str, score: float) -> dict:
    return {"entry_id": entry_id, "score": score}


class _Cards:
    """A `read_cards` that records its calls, like `rag.entries.entry_cards` over a database."""

    def __init__(self, cards=CARDS) -> None:
        self.cards = cards
        self.calls: list[list[str]] = []

    def __call__(self, ids):
        self.calls.append(list(ids))
        return {i: self.cards[i] for i in ids if i in self.cards}


def _knowledge(cards=None, *, floor=0.5, **row_kw):
    cards = _Cards() if cards is None else cards
    served = view.present_run(_row(_v4(), **row_kw), floor, _alerts({}), cards)
    return served, cards


def _agrees(served: dict) -> None:
    """The panel says the number the `rag` pair says for the same run, and never another."""
    knowledge, rag = served["knowledge"], served["rag"]
    if knowledge["state"] == "matched":
        assert knowledge["best_pct"] == rag["best_pct"] is not None
        assert rag["below_floor_pct"] is None
    elif knowledge["state"] == "below_floor":
        assert knowledge["best_pct"] == rag["below_floor_pct"] is not None
        assert knowledge["floor_pct"] == rag["floor_pct"]
        assert rag["best_pct"] is None
    else:
        assert knowledge["best_pct"] is None
        assert rag["below_floor_pct"] is None
        if knowledge["state"] != "no_lookup":
            assert rag["best_pct"] is None


def test_knowledge_of_a_matched_run_lists_the_top_three_with_title_and_conclusion():
    matches = [_m(E1, 0.87), _m(E2, 0.6)]
    ranked = [_r(E1, 0.87), _r(E2, 0.6), _r(E3, 0.2), _r(E4, 0.1)]
    served, cards = _knowledge(matches=matches, ranked=ranked)
    assert served["knowledge"] == {
        "state": "matched",
        "failure": None,
        "best_pct": 87,
        "floor_pct": 50,
        "threshold_pct": 0,
        "scored": 4,
        "candidates": [
            {"pct": 87, "title": "Quy tắc một", "conclusion": "confirmed_incident"},
            {"pct": 60, "title": "Quy tắc hai", "conclusion": "false_positive"},
            {"pct": 20, "title": None, "conclusion": "closed_fp"},
        ],
    }
    assert set(served["knowledge"]) == KNOWLEDGE_KEYS
    assert cards.calls == [[E1, E2, E3]]  # one read, for the listed three
    _agrees(served)


def test_knowledge_of_a_run_under_the_floor_cuts_the_number_down_and_agrees_with_the_pair():
    served, _ = _knowledge(ranked=[_r(E1, 0.4999), _r(E2, 0.3)], matches=[])
    assert served["knowledge"]["state"] == "below_floor"
    assert served["knowledge"]["best_pct"] == 49 and served["knowledge"]["floor_pct"] == 50
    assert [c["pct"] for c in served["knowledge"]["candidates"]] == [49, 30]
    assert served["rag"]["below_floor_pct"] == 49 and served["rag"]["floor_pct"] == 50
    _agrees(served)


def test_knowledge_of_a_lookup_with_nothing_that_counts_is_no_candidate_and_reads_no_entry():
    served, cards = _knowledge(matches=[], ranked=[])
    assert served["knowledge"] == {
        "state": "no_candidate",
        "failure": None,
        "best_pct": None,
        "floor_pct": 50,
        "threshold_pct": 0,
        "scored": 0,
        "candidates": [],
    }
    assert cards.calls == []  # nothing listed, nothing read
    _agrees(served)


def test_knowledge_of_a_failed_lookup_names_the_closed_kind():
    kind = FAILURE_KINDS[0]
    served, cards = _knowledge(warnings=[rag_not_applied_warning(kind)], matches=None, ranked=None)
    assert served["knowledge"]["state"] == "failed" and served["knowledge"]["failure"] == kind
    assert served["knowledge"]["candidates"] == [] and served["knowledge"]["scored"] is None
    assert cards.calls == []
    _agrees(served)


def test_knowledge_of_a_run_with_no_lookup_is_no_lookup():
    served, cards = _knowledge(matches=None, ranked=None)
    assert served["knowledge"]["state"] == "no_lookup"
    assert served["knowledge"]["floor_pct"] is None and served["knowledge"]["scored"] is None
    assert cards.calls == []
    _agrees(served)


def test_knowledge_threshold_is_always_zero_for_a_case():
    """② has no RAG verdict rule: the key is there for the one shape both tiers' panels have."""
    for kw in (
        {"matches": [_m(E1, 0.87)], "ranked": [_r(E1, 0.87)]},
        {"matches": [], "ranked": [_r(E1, 0.3)]},
        {"matches": None, "ranked": None},
    ):
        assert _knowledge(**kw)[0]["knowledge"]["threshold_pct"] == 0


def test_knowledge_of_an_entry_that_is_gone_has_no_title_and_no_conclusion():
    served, _ = _knowledge(_Cards({}), matches=[_m(E1, 0.9)], ranked=[_r(E1, 0.9)])
    assert served["knowledge"]["candidates"] == [{"pct": 90, "title": None, "conclusion": None}]


def test_knowledge_without_a_card_reader_lists_candidates_without_titles():
    served = view.present_run(
        _row(_v4(), matches=[_m(E1, 0.9)], ranked=[_r(E1, 0.9)]), 0.5, _alerts({})
    )
    assert served["knowledge"]["candidates"] == [{"pct": 90, "title": None, "conclusion": None}]


def test_knowledge_without_a_floor_has_no_floor_and_no_below_floor_state():
    served = view.present_run(
        _row(_v4(), matches=[], ranked=[_r(E1, 0.3)]), None, _alerts({}), _Cards()
    )
    assert served["knowledge"]["state"] == "no_candidate"
    assert served["knowledge"]["floor_pct"] is None


def test_knowledge_of_a_run_that_stopped_is_not_there():
    row = (
        uuid.uuid4(),
        CREATED,
        "schema",
        None,
        None,
        None,
        None,
        [_m(E1, 0.9)],
        [_r(E1, 0.9)],
        1,
        2,
        3,
        0.1,
    )
    assert "knowledge" not in view.present_run(row, 0.5, _alerts({}), _Cards())


def test_knowledge_is_json_plain_and_the_rag_pair_is_as_it_was():
    served, _ = _knowledge(matches=[], ranked=[_r(E1, 0.47)])
    json.dumps(served["knowledge"])
    assert served["rag"] == {
        "best_pct": None,
        "not_applied": None,
        "below_floor_pct": 47,
        "floor_pct": 50,
    }


def test_a_reader_that_returns_junk_for_a_card_gives_no_title():
    class _Junk:
        def __call__(self, ids):
            return {i: "not a pair" for i in ids}

    served = view.present_run(
        _row(_v4(), matches=[_m(E1, 0.9)], ranked=[_r(E1, 0.9)]), 0.5, _alerts({}), _Junk()
    )
    assert served["knowledge"]["candidates"] == [{"pct": 90, "title": None, "conclusion": None}]


# --------------------------------------------------------------------------- the tripwire

#: A module of `backend/app` that names a hypothesis's `likelihood` (the one word of the new Tier 2 fields no other
#: part of the product uses): the schema and the template that ask for it, the readers, and the docstrings of the
#: prompt builders that say they never read it. The words are the model's, about untrusted data: a new module that
#: appears here is a new reader, and must be read by someone who knows the rule (spec 4) - never fed back into a prompt.
MAY_NAME_LIKELIHOOD = {
    "llm/investigate.py",
    "llm/results.py",
    "llm/templates/investigate_system.txt",
    "llm/templates/output_schemas.json",
    "rag/draft.py",
    "tier2/dossier.py",
    "tier2/investigation_view.py",
}


def test_only_the_expected_modules_name_the_tier_2_analyst_fields():
    app = pathlib.Path(__file__).resolve().parents[1] / "app"
    found = {
        str(path.relative_to(app))
        for path in app.rglob("*")
        if path.suffix in {".py", ".json", ".txt"} and "likelihood" in path.read_text("utf-8")
    }
    assert found == MAY_NAME_LIKELIHOOD


# The prompt-side modules are the ones a stored answer could be carried through into a model's prompt. Three of them
# name `likelihood` in prose today - `llm/investigate.py` (twice), `tier2/dossier.py` and `rag/draft.py` (once each),
# every time to say it is NOT read - so the module list above would let a read added to one of them pass. Two pins
# close that. (1) The number of times each names the word is exactly what it is today: a new mention, a comment or a
# read, changes the count and sends the person who made it here. (2) None of the prompt-side modules names a field of
# the new Tier 2 shape IN CODE: no string constant that is exactly `likelihood`, `timeline`, `scope` or `priority`
# (`result.get("timeline")`, `step["priority"]`), no identifier `likelihood`, and none of the page-side readers of
# `llm/results.py` that read them (`timeline_entries`, `timeline_alert_ids`, `scope_lists`, `next_step_rows`). The words
# `timeline` and `scope` are ordinary in the dossier's own case timeline and scope blocks (`_block3_timeline`,
# `HEADING_SCOPE`): only the exact constant is a key of the stored answer, so an identifier that holds them is not
# flagged. Prose (docstrings and comments) is not code.
PROMPT_SIDE = (
    "llm/investigate.py",
    "tier2/dossier.py",
    "rag/draft.py",
    "llm/builder.py",
    "llm/triage.py",
    "tier1/triage.py",
)
#: How many times each of the three names the word `likelihood` today (all of them prose).
LIKELIHOOD_MENTIONS = {"llm/investigate.py": 2, "tier2/dossier.py": 1, "rag/draft.py": 1}
FIELD_KEYS = frozenset({"likelihood", "timeline", "scope", "priority"})
PAGE_SIDE_READERS = frozenset(
    {"timeline_entries", "timeline_alert_ids", "scope_lists", "next_step_rows"}
)


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def names_a_new_field_in_code(source: str) -> list[str]:
    """What of the new Tier 2 fields the code of `source` names (see above), as text; `[]` for none."""
    tree = ast.parse(source)
    skip = _docstring_ids(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            if node.value in FIELD_KEYS:
                found.append(f"constant {node.value!r}")
            continue
        names: list[str] = []
        if isinstance(node, ast.Name):
            names = [node.id]
        elif isinstance(node, ast.Attribute):
            names = [node.attr]
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names = [node.name]
        elif isinstance(node, ast.arg | ast.keyword) and node.arg:
            names = [node.arg]
        elif isinstance(node, ast.alias):
            names = [node.name.rpartition(".")[2], node.asname or ""]
        for name in names:
            if name in PAGE_SIDE_READERS or "likelihood" in name.lower():
                found.append(f"name {name!r}")
    return found


def test_the_prompt_side_modules_mention_likelihood_exactly_as_often_as_today():
    app = pathlib.Path(__file__).resolve().parents[1] / "app"
    counts = {
        path: (app / path).read_text("utf-8").count("likelihood") for path in LIKELIHOOD_MENTIONS
    }
    assert counts == LIKELIHOOD_MENTIONS


def test_no_prompt_side_module_names_a_new_tier_2_field_in_code():
    app = pathlib.Path(__file__).resolve().parents[1] / "app"
    found = {
        path: names_a_new_field_in_code((app / path).read_text("utf-8")) for path in PROMPT_SIDE
    }
    assert found == {path: [] for path in PROMPT_SIDE}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('x = result.get("timeline")', ["constant 'timeline'"]),
        ('x = h["likelihood"]', ["constant 'likelihood'"]),
        ('rows = [s["priority"] for s in steps]', ["constant 'priority'"]),
        ('scope = result.get("scope")', ["constant 'scope'"]),
        ("likelihood = 3", ["name 'likelihood'"]),
        ("x = row.likelihood", ["name 'likelihood'"]),
        ("from app.llm.results import timeline_entries", ["name 'timeline_entries'"]),
        ("import app.llm.results as r\nr.scope_lists(x)", ["name 'scope_lists'"]),
        ("f(next_step_rows=1)", ["name 'next_step_rows'"]),
        # prose is not code, and the dossier's own words are not the stored answer's keys
        ('"""A docstring that says likelihood and timeline."""\nx = 1', []),
        ("# result.get('timeline') in a comment\nx = 1", []),
        ('HEADING_TIMELINE = "## Diễn biến"\ntimeline_rows = []\nscope_block = 1', []),
        ('STEP = "timeline_cap_300"', []),
    ],
)
def test_the_scan_for_the_new_fields_in_code_finds_what_it_should(source, expected):
    assert names_a_new_field_in_code(source) == expected


def test_the_guards_go_red_on_a_scratch_copy_of_a_prompt_builder(tmp_path):
    """Never in the real file: the dossier's source with one line added that reads the field is flagged by the scan,
    and counted by the pin."""
    real = (pathlib.Path(__file__).resolve().parents[1] / "app" / "tier2" / "dossier.py").read_text(
        "utf-8"
    )
    scratch = tmp_path / "dossier_copy.py"
    scratch.write_text(real + '\nLEAK = {"h": block.get("likelihood")}\n', "utf-8")
    text = scratch.read_text("utf-8")
    assert names_a_new_field_in_code(real) == []
    assert names_a_new_field_in_code(text) == ["constant 'likelihood'"]
    assert text.count("likelihood") == LIKELIHOOD_MENTIONS["tier2/dossier.py"] + 1
