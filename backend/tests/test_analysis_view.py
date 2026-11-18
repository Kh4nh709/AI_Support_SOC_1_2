"""DEC-221, card AP-T2: `tier1.analysis.build`, the `analysis` object of the Tier 1 alert view
(`docs/superpowers/specs/2026-11-15-ai-analysis-panel-redesign.md` section 5). PURE: no database, no socket. The
reader that feeds it (`tier1.queue.get_alert_view`) and the blind arm are tested in `test_analysis_db.py`.

`build` takes one stored run (the columns of the newest proposer row the alert view already reads), the alert's MITRE
ids, the RAG floor and a function that reads the title and the conclusion of knowledge entries, and returns the
object the panel is drawn from. Everything in it is data the system already stores; nothing is asked of a model.

What the file pins, part by part: the five model-written texts; every reason with its verified flag and its closed
reason; the facts table; the checks, their closed `detail` codes and the tile's figures; the RAG block; the history;
the playbook and the rule that matches today; the server-built highlights; the technical figures; and, for a run
the RAG default of DEC-219 applied to, that none of the model's own answer is served.
"""

from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import decimal
import itertools

import pytest
from app.kb.lookup import get_decision_table
from app.llm import rag_view, verdicts
from app.rag.failures import FAILURE_KINDS
from app.tier1 import analysis, queue

NOW = dt.datetime(2026, 11, 15, 9, 30, tzinfo=dt.UTC)

FACTS = {
    "severity": "high",
    "category": "brute_force",
    "rule_level": 10,
    "occurrence_count": 4,
    "ioc_reputation": "malicious",
    "asset_criticality": "medium",
    "identity_privileged": "false",
    "correlated_clusters": 2,
    "correlated_by_category": {"brute_force": 2},
    "first_seen_at": "2026-11-15T08:00:00+00:00",
    "last_seen_at": "2026-11-15T09:00:00+00:00",
}
BASIS = {
    "severity": "high",
    "ioc_reputation": "malicious",
    "asset_criticality": "medium",
    "identity_privileged": "false",
    "occurrence_count": 4,
    "playbook_rule_applied": None,
}
REASONS = [
    {"claim": "claim one", "quote": "quote one", "source": "wazuh_raw_log"},
    {"claim": "claim two", "quote": "quote two", "source": "rule_description"},
    {"claim": "claim three", "quote": "quote three", "source": "context"},
]
TEXTS = {
    "summary": "Tóm tắt của mô hình.",
    "reading_attack": "Đọc theo hướng tấn công.",
    "reading_benign": "Đọc theo hướng lành tính.",
    "would_change": "Điều sẽ làm đổi kết luận.",
    "next_checks": ["kiểm tra một", "kiểm tra hai", "kiểm tra ba", "kiểm tra bốn"],
}
RAW = {
    "suggested_action": "true_positive",
    "confidence": "high",
    "structured_basis": BASIS,
    "reasons": REASONS,
    "playbook_used": None,
    **TEXTS,
}
STEPS = {
    "1": "ok",
    "2": "ok",
    "3": "dropped:0",
    "3r": "n/a",
    "4": "n/a",
    "5": "findings:0",
    "6": "agree",
    "7": "ok",
}


def _gate(**over) -> dict:
    """A version 2 `gate_result` of a clean true_positive run."""
    gate = {
        "version": 2,
        "proposed_verdict": "true_positive",
        "final_verdict": "true_positive",
        "forced": False,
        "forced_by": [],
        "flagged_by": [],
        "rag_rule": {"threshold": 0, "best_pct": None, "applied": False, "changed": False},
        "step1_errors": [],
        "steps": dict(STEPS),
        "hallucination_flag": False,
        "mismatched_fields": [],
        "dropped_reasons": [],
        "missing": [],
        "facts": dict(FACTS),
        "warnings": [],
        "verifier_verdict": "true_positive",
        "playbook_used_effective": None,
        "prompt_version": "abc",
        "proposer_raw": copy.deepcopy(RAW),
    }
    gate.update(over)
    return gate


_DEFAULT = object()


def _run(
    *,
    result=_DEFAULT,
    gate=_DEFAULT,
    matches=None,
    ranked=None,
    history=None,
    warnings=None,
    **cols,
) -> analysis.StoredRun:
    return analysis.StoredRun(
        result=copy.deepcopy(RAW) if result is _DEFAULT else result,
        gate_result=_gate() if gate is _DEFAULT else gate,
        created_at=cols.get("created_at", NOW),
        citation_warnings=warnings,
        matches=matches,
        ranked=ranked,
        history=history,
        input_tokens=cols.get("input_tokens", 1200),
        output_tokens=cols.get("output_tokens", 340),
        latency_ms=cols.get("latency_ms", 2100),
        cost_usd=cols.get("cost_usd", decimal.Decimal("0.01234")),
        verifier_input_tokens=cols.get("verifier_input_tokens"),
        verifier_output_tokens=cols.get("verifier_output_tokens"),
        verifier_latency_ms=cols.get("verifier_latency_ms"),
        verifier_cost_usd=cols.get("verifier_cost_usd"),
    )


def _no_cards(_ids):
    return {}


def _build(run, *, mitre_ids=("T1110",), floor=0.5, read_cards=_no_cards):
    return analysis.build(run, mitre_ids=list(mitre_ids), floor=floor, read_cards=read_cards)


def _rows(built):
    return {row["id"]: row for row in built["checks"]}


def _match(score, entry="e1"):
    return {"entry_id": entry, "level": "giong", "content_sha256": "0" * 64, "score": score}


def _cand(score, entry="c1"):
    return {"entry_id": entry, "score": score}


def _walk(value):
    """Every key and every string value, at every depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk(item)
    elif isinstance(value, str):
        yield value


# ── the shape ───────────────────────────────────────────────────────────────────────────────────


def test_the_analysis_has_exactly_these_keys_in_this_order():
    built = _build(_run())
    assert list(built) == [
        "summary",
        "reading_attack",
        "reading_benign",
        "would_change",
        "next_checks",
        "reasons",
        "facts",
        "checks",
        "check_totals",
        "rag",
        "history",
        "playbook",
        "highlights",
        "tech",
    ]


def test_a_run_with_no_result_has_no_analysis():
    assert _build(_run(result=None)) is None


@pytest.mark.parametrize("junk", [[], "x", 7, True])
def test_a_result_that_is_not_an_object_has_no_analysis(junk):
    assert _build(_run(result=junk)) is None


def test_the_stored_run_has_no_column_for_the_model():
    """G5: the model's name is never read, so it cannot be served."""
    assert not any("model" in name for name in analysis.StoredRun.__dataclass_fields__)


# ── the model-written texts ─────────────────────────────────────────────────────────────────────


def test_the_five_texts_come_from_the_stored_result_and_next_checks_is_cut_to_three():
    built = _build(_run())
    assert built["summary"] == TEXTS["summary"]
    assert built["reading_attack"] == TEXTS["reading_attack"]
    assert built["reading_benign"] == TEXTS["reading_benign"]
    assert built["would_change"] == TEXTS["would_change"]
    assert built["next_checks"] == TEXTS["next_checks"][:3]
    assert analysis.NEXT_CHECKS_SHOWN == 3


def test_a_run_stored_before_version_4_has_no_text_and_no_next_checks():
    old = {k: v for k, v in RAW.items() if k not in TEXTS}
    built = _build(_run(result=old, gate=_gate(proposer_raw=old)))
    assert [built[k] for k in ("summary", "reading_attack", "reading_benign", "would_change")] == [
        None
    ] * 4
    assert built["next_checks"] == []


@pytest.mark.parametrize("junk", [None, "", "   ", 7, True, ["x"], {"a": 1}])
def test_a_text_that_is_not_text_is_none(junk):
    built = _build(_run(result={**RAW, "summary": junk, "would_change": junk}))
    assert built["summary"] is None and built["would_change"] is None


@pytest.mark.parametrize("junk", [None, "one string", 7, {"a": "b"}, []])
def test_next_checks_that_is_not_a_list_is_empty(junk):
    assert _build(_run(result={**RAW, "next_checks": junk}))["next_checks"] == []


def test_next_checks_keeps_only_the_non_blank_strings_before_it_cuts():
    built = _build(_run(result={**RAW, "next_checks": [None, "", " ", 3, "a", "b", "c", "d"]}))
    assert built["next_checks"] == ["a", "b", "c"]


def test_the_texts_are_served_as_they_were_stored():
    """Served as text, never altered: no trimming, no markup."""
    odd = "  <b>bold</b> {{x}} \n second line "
    assert _build(_run(result={**RAW, "summary": odd}))["summary"] == odd


# ── the reasons ─────────────────────────────────────────────────────────────────────────────────


def test_every_reason_of_the_models_answer_is_served_in_its_order_with_whether_it_was_verified():
    gate = _gate(
        dropped_reasons=[
            {"index": 0, "why": "not_substring"},
            {"index": 2, "why": "unknown_source"},
        ],
        steps={**STEPS, "3": "dropped:2"},
    )
    survivors = [REASONS[1]]
    built = _build(_run(result={**RAW, "reasons": survivors}, gate=gate))
    assert built["reasons"] == [
        {**REASONS[0], "verified": False, "why": "not_substring"},
        {**REASONS[1], "verified": True, "why": None},
        {**REASONS[2], "verified": False, "why": "unknown_source"},
    ]


def test_the_three_closed_reasons_a_quote_can_fail_for():
    assert analysis.REASON_WHY == ("not_substring", "unknown_source", "empty_quote")
    for why in analysis.REASON_WHY:
        gate = _gate(dropped_reasons=[{"index": 1, "why": why}])
        got = _build(_run(gate=gate))["reasons"][1]
        assert (got["verified"], got["why"]) == (False, why)


def test_why_is_null_exactly_when_the_reason_is_verified():
    gate = _gate(dropped_reasons=[{"index": 0, "why": "empty_quote"}])
    for row in _build(_run(gate=gate))["reasons"]:
        assert (row["why"] is None) is row["verified"]


@pytest.mark.parametrize("why", ["whatever", None, 3, ["x"]])
def test_an_unverified_reason_whose_recorded_code_is_not_closed_is_not_substring(why):
    gate = _gate(dropped_reasons=[{"index": 0, "why": why}])
    got = _build(_run(gate=gate))["reasons"][0]
    assert (got["verified"], got["why"]) == (False, "not_substring")


def test_a_reason_the_gate_dropped_twice_or_out_of_range_changes_nothing_else():
    gate = _gate(
        dropped_reasons=[
            {"index": 1, "why": "empty_quote"},
            {"index": 1, "why": "x"},
            {"index": 99, "why": "x"},
            "junk",
            {"why": "x"},
            {"index": True, "why": "x"},
        ]
    )
    rows = _build(_run(gate=gate))["reasons"]
    assert [r["verified"] for r in rows] == [True, False, True]
    assert rows[1]["why"] == "empty_quote"  # the first record of an index wins


def test_a_reason_that_is_not_an_object_is_skipped_and_the_indexes_still_line_up():
    raw = {**RAW, "reasons": ["junk", REASONS[0], None, REASONS[1]]}
    gate = _gate(proposer_raw=raw, dropped_reasons=[{"index": 3, "why": "not_substring"}])
    rows = _build(_run(result={**RAW, "reasons": [REASONS[0]]}, gate=gate))["reasons"]
    assert [(r["claim"], r["verified"]) for r in rows] == [
        ("claim one", True),
        ("claim two", False),
    ]


def test_a_reasons_fields_are_text_or_none():
    raw = {**RAW, "reasons": [{"claim": 1, "quote": None, "source": ["x"]}, {"claim": "c"}]}
    rows = _build(_run(gate=_gate(proposer_raw=raw)))["reasons"]
    assert rows[0] == {"claim": None, "quote": None, "source": None, "verified": True, "why": None}
    assert rows[1] == {"claim": "c", "quote": None, "source": None, "verified": True, "why": None}


@pytest.mark.parametrize("raw", [None, {}, {"reasons": "x"}, {"reasons": None}, "junk", []])
def test_without_the_models_raw_reasons_the_stored_survivors_are_served_as_verified(raw):
    """A garbled or missing `proposer_raw` gives less, never an error: what the gate stored (the survivors of step
    3, which is all that is stored) is served, and a survivor is verified by construction."""
    gate = _gate(proposer_raw=raw)
    rows = _build(_run(result={**RAW, "reasons": [REASONS[1]]}, gate=gate))["reasons"]
    assert rows == [{**REASONS[1], "verified": True, "why": None}]


def test_a_run_with_no_reasons_serves_an_empty_list():
    assert (
        _build(
            _run(result={**RAW, "reasons": []}, gate=_gate(proposer_raw={**RAW, "reasons": []}))
        )["reasons"]
        == []
    )


# ── the facts ───────────────────────────────────────────────────────────────────────────────────


def test_the_facts_are_the_five_the_gate_compares_in_a_fixed_order():
    assert analysis.FACT_FIELDS == (
        "severity",
        "ioc_reputation",
        "asset_criticality",
        "identity_privileged",
        "occurrence_count",
    )
    built = _build(_run())
    assert [row["field"] for row in built["facts"]] == list(analysis.FACT_FIELDS)
    assert built["facts"][0] == {
        "field": "severity",
        "system": "high",
        "model": "high",
        "match": True,
    }
    assert built["facts"][4] == {
        "field": "occurrence_count",
        "system": 4,
        "model": 4,
        "match": True,
    }


def test_a_field_step_2_recorded_as_mismatched_is_not_a_match():
    basis = {**BASIS, "severity": "low", "occurrence_count": 9}
    gate = _gate(
        proposer_raw={**RAW, "structured_basis": basis},
        mismatched_fields=["severity", "occurrence_count"],
        steps={**STEPS, "2": "mismatch"},
        flagged_by=["step2"],
    )
    facts = {row["field"]: row for row in _build(_run(gate=gate))["facts"]}
    assert facts["severity"] == {
        "field": "severity",
        "system": "high",
        "model": "low",
        "match": False,
    }
    assert facts["occurrence_count"] == {
        "field": "occurrence_count",
        "system": 4,
        "model": 9,
        "match": False,
    }
    assert facts["ioc_reputation"]["match"] is True


def test_a_count_the_system_does_not_have_is_not_compared():
    """SOAR sends one representative of a case: no number to check the model's against (DEC-209 item 2)."""
    gate = _gate(facts={**FACTS, "occurrence_count": None})
    row = _build(_run(gate=gate))["facts"][4]
    assert row == {"field": "occurrence_count", "system": None, "model": 4, "match": None}


def test_a_declared_boolean_is_served_as_the_closed_string_the_gate_compares():
    basis = {**BASIS, "identity_privileged": True}
    gate = _gate(proposer_raw={**RAW, "structured_basis": basis})
    assert _build(_run(gate=gate))["facts"][3]["model"] == "true"


def test_without_a_basis_or_without_step_2_the_model_column_and_the_match_are_none():
    gate = _gate(proposer_raw={**RAW, "structured_basis": None})
    for row in _build(_run(gate=gate))["facts"]:
        assert row["model"] is None and row["match"] is None
        assert row["system"] is not None
    steps = {k: v for k, v in STEPS.items() if k != "2"}
    for row in _build(_run(gate=_gate(steps=steps)))["facts"]:
        assert row["match"] is None


@pytest.mark.parametrize("facts", [None, [], "x", {}])
def test_without_system_facts_the_system_column_is_none(facts):
    for row in _build(_run(gate=_gate(facts=facts)))["facts"]:
        assert row["system"] is None and row["match"] is None


# ── the checks ──────────────────────────────────────────────────────────────────────────────────


def test_the_ids_the_outcomes_and_every_detail_code_are_pinned():
    assert analysis.CHECK_IDS == (
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
    )  # no row for the RAG rule: Tier 1 is not told
    assert analysis.CHECK_OUTCOMES == ("pass", "warn", "na")
    assert analysis.CHECK_DETAILS == (
        "schema_ok",
        "schema_repaired",
        "facts_match",
        "facts_mismatch",
        "quotes_verified",
        "quotes_some_dropped",
        "no_verified_quote",
        "fp_policy_ok",
        "fp_policy_facts",
        "fp_policy_playbook",
        "not_false_positive",
        "no_injection_findings",
        "injection_findings",
        "verifier_agrees",
        "verifier_disagrees",
        "verifier_invalid",
        "not_run",
    )


def test_a_clean_true_positive_run_has_six_rows_and_passes_what_applies():
    built = _build(_run())
    assert built["checks"] == [
        {"id": "1", "outcome": "pass", "detail": "schema_ok"},
        {"id": "2", "outcome": "pass", "detail": "facts_match"},
        {"id": "3", "outcome": "pass", "detail": "quotes_verified"},
        {"id": "4", "outcome": "na", "detail": "not_false_positive"},
        {"id": "5", "outcome": "pass", "detail": "no_injection_findings"},
        {"id": "6", "outcome": "pass", "detail": "verifier_agrees"},
    ]
    assert built["check_totals"] == {"passed": 5, "applicable": 5, "warnings": 0}


def test_a_clean_false_positive_run_also_checks_the_policy():
    gate = _gate(
        proposed_verdict="false_positive",
        final_verdict="false_positive",
        steps={**STEPS, "4": "ok"},
    )
    built = _build(_run(gate=gate))
    assert _rows(built)["4"] == {"id": "4", "outcome": "pass", "detail": "fp_policy_ok"}
    assert built["check_totals"] == {"passed": 6, "applicable": 6, "warnings": 0}


def test_every_step_that_flags_is_a_warning_with_its_own_code():
    gate = _gate(
        proposed_verdict="false_positive",
        final_verdict="false_positive",
        flagged_by=["step2", "step3", "step4", "step6"],
        steps={
            "1": "repaired",
            "2": "mismatch",
            "3": "dropped:3",
            "3r": "n/a",
            "4": "missing",
            "5": "findings:2",
            "6": "disagree",
            "7": "ok",
        },
        missing=["severity", "playbook_rule"],
        mismatched_fields=["severity"],
    )
    built = _build(_run(gate=gate))
    assert built["checks"] == [
        {"id": "1", "outcome": "pass", "detail": "schema_repaired"},
        {"id": "2", "outcome": "warn", "detail": "facts_mismatch"},
        {"id": "3", "outcome": "warn", "detail": "no_verified_quote"},
        {"id": "4", "outcome": "warn", "detail": "fp_policy_facts"},
        {"id": "5", "outcome": "warn", "detail": "injection_findings"},
        {"id": "6", "outcome": "warn", "detail": "verifier_disagrees"},
    ]
    assert built["check_totals"] == {"passed": 1, "applicable": 6, "warnings": 5}


def test_step_3_that_dropped_some_but_kept_one_still_passes_and_says_so():
    gate = _gate(
        steps={**STEPS, "3": "dropped:1"}, dropped_reasons=[{"index": 0, "why": "not_substring"}]
    )
    assert _rows(_build(_run(gate=gate)))["3"] == {
        "id": "3",
        "outcome": "pass",
        "detail": "quotes_some_dropped",
    }


def test_step_4_with_only_the_playbook_rule_missing_says_so():
    gate = _gate(
        proposed_verdict="false_positive",
        final_verdict="false_positive",
        flagged_by=["step4"],
        steps={**STEPS, "4": "missing"},
        missing=["playbook_rule"],
        warnings=["table_unreviewed"],
    )
    assert _rows(_build(_run(gate=gate)))["4"] == {
        "id": "4",
        "outcome": "warn",
        "detail": "fp_policy_playbook",
    }


@pytest.mark.parametrize(
    "missing", [["severity"], ["ioc_reputation", "playbook_rule"], [], None, "x"]
)
def test_step_4_missing_anything_but_the_playbook_alone_is_the_facts_code(missing):
    gate = _gate(
        proposed_verdict="false_positive",
        final_verdict="false_positive",
        steps={**STEPS, "4": "missing"},
        missing=missing,
    )
    assert _rows(_build(_run(gate=gate)))["4"]["detail"] == "fp_policy_facts"


@pytest.mark.parametrize(
    ("status", "outcome", "detail"),
    [
        ("agree", "pass", "verifier_agrees"),
        ("disagree", "warn", "verifier_disagrees"),
        ("invalid", "warn", "verifier_invalid"),
    ],
)
def test_the_verifiers_row(status, outcome, detail):
    gate = _gate(steps={**STEPS, "6": status})
    assert _rows(_build(_run(gate=gate)))["6"] == {"id": "6", "outcome": outcome, "detail": detail}


#: Every stored shape of `gate_result.rag_rule` (and `steps["3r"]`) a document can carry: DEC-225's seven keys
#: (applied, in either direction, and not applied), DEC-219's four, the switch off, none at all, and junk.
STORED_RULES = [
    (
        {
            "threshold": 80,
            "best_pct": 62,
            "applied": True,
            "changed": True,
            "entry_side": "incident",
            "rule_verdict": "false_positive",
            "basis": "match",
        },
        "changed",
    ),
    (
        {
            "threshold": 80,
            "best_pct": 85,
            "applied": True,
            "changed": False,
            "entry_side": "incident",
            "rule_verdict": "true_positive",
            "basis": "match",
        },
        "applied",
    ),
    (
        {
            "threshold": 80,
            "best_pct": 62,
            "applied": False,
            "changed": False,
            "entry_side": "benign",
            "rule_verdict": None,
            "basis": "match",
        },
        "n/a",
    ),
    ({"threshold": 80, "best_pct": 62, "applied": True, "changed": True}, "changed"),  # DEC-219
    ({"threshold": 80, "best_pct": 90, "applied": False, "changed": False}, "n/a"),  # DEC-219
    ({"threshold": 0, "best_pct": None, "applied": False, "changed": False}, "n/a"),  # off
    (None, None),  # no `rag_rule` at all
    ("junk", "n/a"),
]


@pytest.mark.parametrize("rule, step", STORED_RULES)
def test_no_document_gives_a_row_for_the_rag_rule(rule, step):
    """DEC-225: Tier 1 is not told that a rule exists. Whatever the stored document says of it, the checks are the six
    of the gate that are warnings or passes about the model's answer, and no detail names the rule.
    """
    steps = dict(STEPS)
    if step is None:
        steps.pop("3r")
    else:
        steps["3r"] = step
    gate = _gate(steps=steps, rag_rule=rule)
    if rule is None:
        del gate["rag_rule"]
    built = _build(_run(gate=gate))
    assert [row["id"] for row in built["checks"]] == ["1", "2", "3", "4", "5"] + (
        [] if verdicts.rag_rule_applied(gate) else ["6"]
    )
    assert "3r" not in {row["id"] for row in built["checks"]}
    assert not {row["detail"] for row in built["checks"]} & {
        "rag_rule_applied",
        "rag_rule_not_applied",
        "rag_rule_off",
    }
    assert "rag_rule" not in repr(built) and "3r" not in repr(built)


def test_a_version_1_document_reads_through_forced_by():
    """Before DEC-217 a failed check forced `needs_review`: `forced_by` names the step, there is no `flagged_by`."""
    gate = _gate(
        version=1,
        proposed_verdict="false_positive",
        final_verdict="needs_review",
        forced=True,
        forced_by=["step3"],
        steps={
            "1": "ok",
            "2": "ok",
            "3": "dropped:1",
            "4": "n/a",
            "5": "findings:0",
            "6": "agree",
            "7": "ok",
        },
        dropped_reasons=[{"index": 0, "why": "empty_quote"}],
    )
    for key in ("flagged_by", "rag_rule", "step1_errors"):
        del gate[key]
    built = _build(
        _run(result={**RAW, "suggested_action": "needs_review", "reasons": []}, gate=gate)
    )
    rows = _rows(built)
    assert rows["3"] == {"id": "3", "outcome": "warn", "detail": "no_verified_quote"}
    # step 4 did not run because the old gate had forced the verdict: that is "not run", not "not a false positive"
    assert rows["4"] == {"id": "4", "outcome": "na", "detail": "not_run"}
    assert "3r" not in rows
    assert built["reasons"][0] == {**REASONS[0], "verified": False, "why": "empty_quote"}


@pytest.mark.parametrize("steps", [None, [], "x", 7, {}])
def test_a_document_with_no_steps_has_six_rows_that_were_not_run(steps):
    built = _build(_run(gate=_gate(steps=steps)))
    assert [row["id"] for row in built["checks"]] == list(analysis.CHECK_IDS)
    assert {row["outcome"] for row in built["checks"]} == {"na"}
    assert {row["detail"] for row in built["checks"]} <= {"not_run", "not_false_positive"}
    assert built["check_totals"] == {"passed": 0, "applicable": 0, "warnings": 0}


@pytest.mark.parametrize("gate", [None, [], "x", {}])
def test_a_missing_or_garbled_gate_document_still_gives_an_analysis(gate):
    built = _build(_run(gate=gate))
    assert built is not None
    assert built["check_totals"] == {"passed": 0, "applicable": 0, "warnings": 0}
    assert built["facts"][0]["system"] is None
    assert built["history"] is None and built["rag"]["state"] == "no_lookup"
    assert built["playbook"] == {
        "name": None,
        "rule_id": None,
        "rule_action": None,
        "rule_table_reviewed": None,
    }


def test_the_totals_are_derived_from_the_rows_and_add_up():
    statuses = {
        "1": ["ok", "repaired", None],
        "2": ["ok", "mismatch", None],
        "3": ["dropped:0", "dropped:2", None],
        "4": ["ok", "missing", "n/a", None],
        "5": ["findings:0", "findings:3", "findings:x", None],
        "6": ["agree", "disagree", "invalid", None],
    }
    for combo in itertools.islice(itertools.product(*statuses.values()), 0, None, 7):
        steps = {k: v for k, v in zip(statuses, combo, strict=True) if v is not None}
        built = _build(_run(gate=_gate(steps=steps)))
        rows = built["checks"]
        passed = sum(r["outcome"] == "pass" for r in rows)
        warns = sum(r["outcome"] == "warn" for r in rows)
        applies = sum(r["outcome"] != "na" for r in rows)
        assert built["check_totals"] == {"passed": passed, "applicable": applies, "warnings": warns}
        assert applies == passed + warns
        for row in rows:
            assert row["outcome"] in analysis.CHECK_OUTCOMES
            assert row["detail"] in analysis.CHECK_DETAILS


# ── the RAG block ───────────────────────────────────────────────────────────────────────────────


def _cards(mapping):
    calls = []

    def read(ids):
        calls.append(list(ids))
        return {i: mapping[i] for i in ids if i in mapping}

    read.calls = calls  # type: ignore[attr-defined]
    return read


def test_a_matched_run_lists_its_best_three_with_the_entries_title_and_conclusion():
    cards = _cards(
        {
            "a": ("Tiêu đề A", "confirmed_incident"),
            "b": ("Tiêu đề B", "closed_fp"),
            "c": ("Tiêu đề C", "closed_benign"),
        }
    )
    run = _run(
        matches=[_match(0.87, "a"), _match(0.61, "b")],
        ranked=[_cand(0.87, "a"), _cand(0.61, "b"), _cand(0.47, "c"), _cand(0.3, "d")],
        gate=_gate(rag_rule={"threshold": 80, "best_pct": 87, "applied": False, "changed": False}),
    )
    rag = _build(run, read_cards=cards)["rag"]
    assert rag == {
        "state": "matched",
        "failure": None,
        "best_pct": 87,
        "floor_pct": 50,
        "threshold_pct": 0,  # the rule's threshold is not served (DEC-225): the key stays, as ②'s has it
        "scored": 4,
        "candidates": [
            {"pct": 87, "title": "Tiêu đề A", "conclusion": "confirmed_incident"},
            {"pct": 61, "title": "Tiêu đề B", "conclusion": "closed_fp"},
            {"pct": 47, "title": "Tiêu đề C", "conclusion": "closed_benign"},
        ],
    }
    assert cards.calls == [
        ["a", "b", "c"]
    ]  # one read, in the ranking's order, only the listed three


def test_an_entry_that_is_gone_gives_a_row_with_no_title_and_no_conclusion():
    cards = _cards({"a": ("Tiêu đề A", "closed_fp")})
    run = _run(matches=[], ranked=[_cand(0.47, "a"), _cand(0.31, "gone")])
    rag = _build(run, read_cards=cards)["rag"]
    assert rag["state"] == "below_floor" and rag["best_pct"] == 47
    assert rag["candidates"] == [
        {"pct": 47, "title": "Tiêu đề A", "conclusion": "closed_fp"},
        {"pct": 31, "title": None, "conclusion": None},
    ]


def test_an_entry_with_no_heading_has_a_conclusion_and_no_title():
    cards = _cards({"a": (None, "closed_fp")})
    rag = _build(_run(matches=[], ranked=[_cand(0.4, "a")]), read_cards=cards)["rag"]
    assert rag["candidates"] == [{"pct": 40, "title": None, "conclusion": "closed_fp"}]


@pytest.mark.parametrize(
    "state_args", [{}, {"matches": [], "ranked": []}, {"warnings": ["rag_not_applied:quota"]}]
)
def test_nothing_is_read_for_a_run_with_no_candidate_to_list(state_args):
    cards = _cards({})
    _build(_run(**state_args), read_cards=cards)
    assert cards.calls == []


@pytest.mark.parametrize("kind", FAILURE_KINDS)
def test_a_failed_lookup_is_failed_with_its_closed_kind(kind):
    rag = _build(_run(warnings=[f"rag_not_applied:{kind}"]))["rag"]
    assert (rag["state"], rag["failure"], rag["candidates"]) == ("failed", kind, [])


@pytest.mark.parametrize("rule, _step", STORED_RULES)
def test_the_rules_threshold_is_never_served(rule, _step):
    """DEC-225: the panel's `threshold_pct` is 0 for every stored document - the threshold of a rule Tier 1 is not told
    of is not served - exactly as ②'s panel has it."""
    gate = _gate(rag_rule=rule)
    if rule is None:
        del gate["rag_rule"]
    assert _build(_run(gate=gate))["rag"]["threshold_pct"] == 0


@pytest.mark.parametrize(
    ("matches", "ranked", "warnings"),
    [
        ([_match(0.87)], [_cand(0.87), _cand(0.4)], None),
        ([], [_cand(0.4999), _cand(0.2)], None),
        ([], [], None),
        (None, None, None),
        (None, None, ["rag_not_applied:timeout"]),
        ([_match(0.62)], [_cand(0.62)], ["learned_entries_dropped"]),
    ],
)
def test_the_block_is_the_shared_panel_plus_the_entries_cards(matches, ranked, warnings):
    """What `rag_view.rag_panel` computes (the part the case view will call too), with `{pct, title, conclusion}`
    in place of `{entry_id, pct}`; and its numbers are the DEC-213/220 pair's for the same run."""
    panel = rag_view.rag_panel(
        matches, warnings, FAILURE_KINDS, ranked=ranked, floor=0.5, threshold=0
    )
    pair = rag_view.rag_view(matches, warnings, FAILURE_KINDS, ranked=ranked, floor=0.5)
    rag = _build(_run(matches=matches, ranked=ranked, warnings=warnings))["rag"]
    assert {k: v for k, v in rag.items() if k != "candidates"} == {
        k: v for k, v in panel.items() if k != "candidates"
    }
    assert [c["pct"] for c in rag["candidates"]] == [c["pct"] for c in panel["candidates"]]
    assert rag["best_pct"] in (pair["best_pct"], pair["below_floor_pct"])


# ── the history ─────────────────────────────────────────────────────────────────────────────────

HISTORY = {
    "level": 3,
    "key_name": "rule_host",
    "total": 15,
    "by_conclusion": {
        "tier1_closed_fp": 0,
        "tier1_closed_benign": 1,
        "escalated_open": 0,
        "concluded_fp": 2,
        "concluded_policy_violation": 0,
        "confirmed_incident": 12,
    },
    "last_seen": "2026-11-14T10:00:00+00:00",
    "examples": ["a-1", "a-2"],
}


def test_the_history_is_the_lookups_stored_one_without_its_examples():
    assert _build(_run(history=HISTORY))["history"] == {
        "key": "rule_host",
        "total": 15,
        "by_conclusion": HISTORY["by_conclusion"],
        "last_seen": "2026-11-14T10:00:00+00:00",
    }


def test_the_history_serves_all_six_conclusions_even_for_a_sparse_store():
    sparse = {
        "key_name": "cluster",
        "total": 2,
        "by_conclusion": {"confirmed_incident": 2},
        "last_seen": None,
    }
    got = _build(_run(history=sparse))["history"]
    assert list(got["by_conclusion"]) == list(HISTORY["by_conclusion"])
    assert (
        got["by_conclusion"]["confirmed_incident"] == 2
        and got["by_conclusion"]["concluded_fp"] == 0
    )
    assert got["last_seen"] is None


@pytest.mark.parametrize(
    "junk",
    [
        None,
        [],
        "x",
        7,
        {},
        {"total": 0},
        {"total": -1},
        {"total": True},
        {"total": "5"},
        {"total": 1.5},
    ],
)
def test_a_history_with_nothing_in_it_is_none(junk):
    assert _build(_run(history=junk))["history"] is None


def test_a_history_with_ill_shaped_parts_gives_less_not_an_error():
    odd = {
        "key_name": "not a level",
        "total": 3,
        "by_conclusion": {
            "confirmed_incident": "3",
            "concluded_fp": True,
            "martian": 9,
            "tier1_closed_fp": 2,
            "escalated_open": -1,
        },
        "last_seen": "yesterday",
    }
    got = _build(_run(history=odd))["history"]
    assert got["key"] is None and got["last_seen"] is None
    assert got["by_conclusion"] == {
        "tier1_closed_fp": 2,
        "tier1_closed_benign": 0,
        "escalated_open": 0,
        "concluded_fp": 0,
        "concluded_policy_violation": 0,
        "confirmed_incident": 0,
    }
    assert "martian" not in got["by_conclusion"]
    assert _build(_run(history={**odd, "by_conclusion": "x"}))["history"][
        "by_conclusion"
    ] == dict.fromkeys(HISTORY["by_conclusion"], 0)


# ── the playbook and the rule that matches today ────────────────────────────────────────────────


def test_the_playbook_is_the_tables_and_the_rule_is_the_first_that_matches_the_runs_facts():
    assert get_decision_table("brute_force").playbook == "brute_force_v1"
    built = _build(_run())  # ioc malicious
    assert built["playbook"] == {
        "name": "brute_force_v1",
        "rule_id": "bf-2",
        "rule_action": "true_positive",
        "rule_table_reviewed": get_decision_table("brute_force").reviewed,
    }


def test_a_false_positive_rule_when_the_facts_fit_it():
    facts = {
        **FACTS,
        "severity": "low",
        "rule_level": 3,
        "ioc_reputation": "clean",
        "asset_criticality": "low",
        "occurrence_count": 3,
    }
    built = _build(_run(gate=_gate(facts=facts)))
    assert built["playbook"] == {
        "name": "brute_force_v1",
        "rule_id": "bf-1",
        "rule_action": "false_positive",
        "rule_table_reviewed": get_decision_table("brute_force").reviewed,
    }


def test_a_table_where_no_rule_matches_gives_the_name_and_no_rule():
    facts = {
        **FACTS,
        "severity": "critical",
        "rule_level": 3,
        "ioc_reputation": "clean",
        "asset_criticality": "high",
        "identity_privileged": "false",
    }
    got = _build(_run(gate=_gate(facts=facts)))["playbook"]
    assert got["name"] == "brute_force_v1"
    assert got["rule_id"] is None and got["rule_action"] is None


@pytest.mark.parametrize("category", ["unknown", "no_such_category", None, 7, "", "../x"])
def test_a_category_with_no_table_gives_all_nulls(category):
    got = _build(_run(gate=_gate(facts={**FACTS, "category": category})))["playbook"]
    assert got == {"name": None, "rule_id": None, "rule_action": None, "rule_table_reviewed": None}


def test_facts_that_make_a_rule_condition_raise_give_the_all_null_playbook_not_an_error():
    """A stored fact the table cannot be compared with (`rule_level: "ten"` against `occurrence_lt: 50`) is a failure
    of APPLYING the table: the playbook is all-null (follow-up E), and the rest of the analysis is intact.
    """
    facts = {
        **FACTS,
        "rule_level": "ten",
        "occurrence_count": "many",
        "ioc_reputation": "clean",
        "severity": "medium",
    }
    built = _build(_run(gate=_gate(facts=facts)))
    assert built["playbook"] == {
        "name": None,
        "rule_id": None,
        "rule_action": None,
        "rule_table_reviewed": None,
    }
    assert built["summary"] == TEXTS["summary"]


# ── the highlights ──────────────────────────────────────────────────────────────────────────────


def _codes(built):
    return [row["code"] for row in built["highlights"]]


def test_the_highlight_codes_the_directions_and_the_cap_are_pinned():
    assert analysis.HIGHLIGHT_DIRECTIONS == ("up", "down", "warn")
    assert analysis.HIGHLIGHTS_SHOWN == 4
    assert analysis.HIGHLIGHT_CODES == (
        "history_incident",
        "history_benign",
        "identity_privileged",
        "asset_high",
        "asset_unknown",
        "severity_critical",
        "rag_matched",
        "rag_below_floor",
        "rag_failed",
        "warning_facts_mismatch",
        "warning_no_verified_quote",
        "warning_fp_policy_facts",
        "warning_fp_policy_playbook",
        "warning_injection_findings",
        "warning_verifier_disagrees",
        "warning_verifier_invalid",
    )


def test_a_run_with_nothing_notable_has_no_highlights():
    assert _build(_run())["highlights"] == []


def test_the_history_majority_is_a_highlight_with_its_counts():
    got = _build(_run(history=HISTORY))["highlights"]
    assert got == [
        {"direction": "up", "code": "history_incident", "params": {"count": 12, "total": 15}}
    ]


def test_a_history_that_is_mostly_closed_as_benign_points_down():
    benign = {
        **HISTORY,
        "total": 10,
        "by_conclusion": {
            **HISTORY["by_conclusion"],
            "tier1_closed_fp": 5,
            "tier1_closed_benign": 1,
            "concluded_fp": 1,
            "confirmed_incident": 3,
        },
    }
    assert _build(_run(history=benign))["highlights"] == [
        {"direction": "down", "code": "history_benign", "params": {"count": 7, "total": 10}}
    ]


def test_exactly_half_is_not_a_majority():
    half = {
        **HISTORY,
        "total": 10,
        "by_conclusion": {
            **HISTORY["by_conclusion"],
            "confirmed_incident": 5,
            "tier1_closed_fp": 5,
            "tier1_closed_benign": 0,
            "concluded_fp": 0,
        },
    }
    assert _build(_run(history=half))["highlights"] == []


@pytest.mark.parametrize(
    ("facts", "row"),
    [
        (
            {"identity_privileged": "true"},
            {"direction": "up", "code": "identity_privileged", "params": {}},
        ),
        ({"asset_criticality": "high"}, {"direction": "up", "code": "asset_high", "params": {}}),
        (
            {"asset_criticality": "unknown"},
            {"direction": "warn", "code": "asset_unknown", "params": {}},
        ),
        ({"severity": "critical"}, {"direction": "up", "code": "severity_critical", "params": {}}),
    ],
)
def test_the_system_facts_that_matter(facts, row):
    got = _build(_run(gate=_gate(facts={**FACTS, **facts})))["highlights"]
    assert got == [row]


@pytest.mark.parametrize(
    ("conclusion", "direction"),
    [
        ("confirmed_incident", "up"),
        ("closed_fp", "down"),
        ("closed_benign", "down"),
        ("concluded_fp", "down"),
        ("concluded_policy_violation", "warn"),
        (None, "warn"),
    ],
)
def test_a_kept_match_is_a_highlight_pointing_where_its_entrys_conclusion_points(
    conclusion, direction
):
    cards = _cards({"a": ("T", conclusion)} if conclusion else {})
    run = _run(matches=[_match(0.87, "a")], ranked=[_cand(0.87, "a")])
    got = _build(run, read_cards=cards)["highlights"]
    assert got == [
        {
            "direction": direction,
            "code": "rag_matched",
            "params": {"pct": 87, "conclusion": conclusion},
        }
    ]


def test_a_best_candidate_under_the_floor_is_a_highlight_with_both_numbers():
    run = _run(matches=[], ranked=[_cand(0.47, "a")])
    assert _build(run)["highlights"] == [
        {"direction": "warn", "code": "rag_below_floor", "params": {"pct": 47, "floor_pct": 50}}
    ]


def test_a_failed_lookup_is_a_highlight_with_its_kind():
    got = _build(_run(warnings=["rag_not_applied:quota"]))["highlights"]
    assert got == [{"direction": "warn", "code": "rag_failed", "params": {"failure": "quota"}}]


def test_a_lookup_that_found_nothing_or_was_never_made_is_no_highlight():
    assert _build(_run(matches=[], ranked=[]))["highlights"] == []
    assert _build(_run(matches=None, ranked=None))["highlights"] == []


def test_each_warning_is_a_highlight_named_after_its_check():
    gate = _gate(
        proposed_verdict="false_positive",
        final_verdict="false_positive",
        flagged_by=["step2", "step3", "step4", "step6"],
        steps={
            "1": "ok",
            "2": "mismatch",
            "3": "dropped:3",
            "3r": "n/a",
            "4": "missing",
            "5": "findings:2",
            "6": "invalid",
            "7": "ok",
        },
        missing=["playbook_rule"],
        mismatched_fields=["severity"],
    )
    built = _build(_run(gate=gate))
    assert _codes(built) == [
        "warning_facts_mismatch",
        "warning_no_verified_quote",
        "warning_fp_policy_playbook",
        "warning_injection_findings",
    ]
    assert {row["direction"] for row in built["highlights"]} == {"warn"}
    assert all(row["params"] == {} for row in built["highlights"])


def test_the_highlights_are_cut_to_four_in_the_pinned_order():
    gate = _gate(
        facts={
            **FACTS,
            "identity_privileged": "true",
            "asset_criticality": "high",
            "severity": "critical",
        },
        flagged_by=["step2"],
        steps={**STEPS, "2": "mismatch"},
        mismatched_fields=["severity"],
    )
    built = _build(
        _run(gate=gate, history=HISTORY, matches=[_match(0.9, "a")], ranked=[_cand(0.9, "a")]),
        read_cards=_cards({"a": ("T", "confirmed_incident")}),
    )
    assert _codes(built) == [
        "history_incident",
        "identity_privileged",
        "asset_high",
        "severity_critical",
    ]
    assert len(built["highlights"]) == analysis.HIGHLIGHTS_SHOWN


def test_every_highlight_code_is_in_the_pinned_tuple_and_the_order_follows_it():
    gate = _gate(
        proposed_verdict="false_positive",
        final_verdict="false_positive",
        facts={**FACTS, "asset_criticality": "unknown"},
        flagged_by=["step4", "step6"],
        steps={**STEPS, "4": "missing", "6": "disagree"},
        missing=["asset_criticality"],
    )
    built = _build(_run(gate=gate, matches=[], ranked=[_cand(0.3, "a")]))
    codes = _codes(built)
    assert codes == [
        "asset_unknown",
        "rag_below_floor",
        "warning_fp_policy_facts",
        "warning_verifier_disagrees",
    ]
    assert codes == sorted(codes, key=analysis.HIGHLIGHT_CODES.index)
    assert set(codes) <= set(analysis.HIGHLIGHT_CODES)
    assert all(row["direction"] in analysis.HIGHLIGHT_DIRECTIONS for row in built["highlights"])


def test_the_highlights_are_deterministic():
    run = _run(history=HISTORY, gate=_gate(facts={**FACTS, "identity_privileged": "true"}))
    assert _build(run)["highlights"] == _build(copy.deepcopy(run))["highlights"]


def test_a_highlight_is_never_built_from_the_models_words():
    """Nothing the model wrote is an input of the highlights: its five texts, the whole raw answer the gate kept
    (`proposer_raw`: texts, declared facts, reasons, the rule it cited) and the reasons that were stored change none
    of them. (The system facts, the history, the RAG standing and the checks' outcomes do; they are held fixed.)
    """
    facts = {**FACTS, "severity": "critical", "identity_privileged": "true"}
    base_run = _run(history=HISTORY, gate=_gate(facts=facts))
    base = _build(base_run)["highlights"]
    assert [row["code"] for row in base] == [
        "history_incident",
        "identity_privileged",
        "severity_critical",
    ]

    texts = {
        k: "different " + k for k in ("summary", "reading_attack", "reading_benign", "would_change")
    }
    other_reasons = [
        {"claim": "another claim", "quote": "another quote", "source": "context"},
        {"claim": "and another", "quote": "x", "source": "kb_playbook"},
    ]
    other_raw = {
        **RAW,
        **texts,
        "next_checks": ["z"],
        "reasons": other_reasons,
        "confidence": "low",
        "suggested_action": "false_positive",
        "structured_basis": {
            **BASIS,
            "severity": "low",
            "asset_criticality": "high",
            "identity_privileged": "false",
            "playbook_rule_applied": "bf-1",
        },
        "playbook_used": "some playbook",
    }
    changed = _run(
        result={**other_raw, "reasons": other_reasons[:1]},
        history=HISTORY,
        gate=_gate(facts=facts, proposer_raw=other_raw),
    )
    assert _build(changed)["highlights"] == base
    # the control: the same change to a SYSTEM fact does change them
    assert (
        _build(_run(history=HISTORY, gate=_gate(facts={**facts, "severity": "low"})))["highlights"]
        != base
    )


# ── the technical figures ───────────────────────────────────────────────────────────────────────


def test_the_technical_figures_come_from_the_run_and_the_alert_and_name_no_model():
    built = _build(_run(), mitre_ids=("T1110", "T1078"))
    assert built["tech"] == {
        "input_tokens": 1200,
        "output_tokens": 340,
        "latency_ms": 2100,
        "cost_usd": 0.01234,
        "analysed_at": NOW,
        "mitre_ids": ["T1110", "T1078"],
        "correlated_at_analysis": 2,
    }
    assert isinstance(built["tech"]["cost_usd"], float)
    assert list(built["tech"]) == [
        "input_tokens",
        "output_tokens",
        "latency_ms",
        "cost_usd",
        "analysed_at",
        "mitre_ids",
        "correlated_at_analysis",
    ]


def test_a_figure_the_run_does_not_have_is_none():
    run = _run(
        input_tokens=None, output_tokens=None, latency_ms=None, cost_usd=None, gate=_gate(facts={})
    )
    tech = _build(run, mitre_ids=())["tech"]
    assert (tech["input_tokens"], tech["output_tokens"], tech["latency_ms"], tech["cost_usd"]) == (
        None,
        None,
        None,
        None,
    )
    assert tech["mitre_ids"] == [] and tech["correlated_at_analysis"] is None


@pytest.mark.parametrize("junk", ["12", True, 1.5, [1]])
def test_a_token_count_that_is_not_an_integer_is_none(junk):
    assert _build(_run(input_tokens=junk))["tech"]["input_tokens"] is None


# ── G5: the model's name ────────────────────────────────────────────────────────────────────────


def test_the_analysis_of_a_run_walks_clean_of_any_model_name():
    """The run the function reads has no model column; whatever else is stored, no key or value of what it serves
    names a model."""
    built = _build(
        _run(history=HISTORY, matches=[_match(0.9, "a")], ranked=[_cand(0.9, "a")]),
        read_cards=_cards({"a": ("T", "closed_fp")}),
    )
    for text in _walk(built):
        lowered = str(text).lower()
        assert "model_id" not in lowered and "glm" not in lowered and "gpt" not in lowered, text


# ── DEC-219: what is not served for a run the RAG default applied to ────────────────────────────

APPLIED_GATE = {
    "proposed_verdict": "true_positive",
    "final_verdict": "false_positive",
    "rag_rule": {"threshold": 80, "best_pct": 62, "applied": True, "changed": True},
    "steps": {**STEPS, "3r": "changed", "4": "ok", "6": "disagree"},
    "flagged_by": ["step6"],
    "verifier_verdict": "needs_review",
}


def _applied(**over):
    gate = _gate(**{**APPLIED_GATE, **over})
    result = {**RAW, "suggested_action": "false_positive"}
    return _run(
        result=result,
        gate=gate,
        matches=[_match(0.62, "a")],
        ranked=[_cand(0.62, "a")],
        history=HISTORY,
    )


def test_for_a_run_the_rule_applied_to_the_models_readings_and_what_would_change_it_are_withheld():
    built = _build(_applied(), read_cards=_cards({"a": ("T", "confirmed_incident")}))
    assert built["reading_attack"] is None
    assert built["reading_benign"] is None
    assert built["would_change"] is None


def test_for_such_a_run_the_models_declared_facts_and_the_match_are_withheld_and_the_system_facts_are_served():
    built = _build(_applied(), read_cards=_cards({}))
    for row in built["facts"]:
        assert row["model"] is None and row["match"] is None
        assert row["system"] is not None
    assert [row["field"] for row in built["facts"]] == list(analysis.FACT_FIELDS)


def test_for_such_a_run_the_verifier_row_is_left_out_and_does_not_count():
    built = _build(_applied(), read_cards=_cards({}))
    assert [row["id"] for row in built["checks"]] == ["1", "2", "3", "4", "5"]
    assert built["check_totals"] == {"passed": 5, "applicable": 5, "warnings": 0}
    assert "warning_verifier_disagrees" not in _codes(built)
    assert "verifier" not in " ".join(_walk(built["checks"]))


def test_for_such_a_run_the_summary_the_next_checks_the_reasons_and_the_rest_are_served():
    built = _build(_applied(), read_cards=_cards({"a": ("Tiêu đề", "confirmed_incident")}))
    assert built["summary"] == TEXTS["summary"]
    assert built["next_checks"] == TEXTS["next_checks"][:3]
    assert [r["claim"] for r in built["reasons"]] == ["claim one", "claim two", "claim three"]
    assert built["rag"]["state"] == "matched" and built["rag"]["threshold_pct"] == 0
    assert built["rag"]["candidates"] == [
        {"pct": 62, "title": "Tiêu đề", "conclusion": "confirmed_incident"}
    ]
    assert built["history"]["total"] == 15
    assert built["playbook"]["name"] == "brute_force_v1"
    assert built["tech"]["input_tokens"] == 1200
    assert "3r" not in _rows(built)  # and no row says a rule decided
    assert _rows(built)["4"]["outcome"] == "pass"


def test_what_the_rule_applied_to_serves_is_the_same_whatever_the_model_answered():
    """One PAIR, not a proof. The two stored runs below differ in the fields listed here - the model's verdict and
    confidence, the rule's `changed`, the verifier's answer and the step it flagged, the facts it declared, the
    readings it wrote - and agree on everything else (the reasons, the summary, the playbook outcomes, step 4). Their
    analyses are identical, so none of THOSE fields reaches the analysis. It says nothing about a field the pair
    does not vary: the model's own words in the reasons and the summary are served by design, and what step 4 says
    about the playbook rule is held by `test_served_playbook_rule.py`, which varies it."""
    tp_changed = _applied()
    fp_unchanged_raw = {
        **RAW,
        "suggested_action": "false_positive",
        "confidence": "low",
        "structured_basis": {**BASIS, "severity": "low", "ioc_reputation": "clean"},
        "reading_attack": "an entirely different reading",
        "reading_benign": "another one",
        "would_change": "something else",
    }
    fp_gate = _gate(
        **{
            **APPLIED_GATE,
            "proposed_verdict": "false_positive",
            "rag_rule": {"threshold": 80, "best_pct": 62, "applied": True, "changed": False},
            "steps": {**STEPS, "3r": "applied", "4": "ok", "6": "agree"},
            "flagged_by": [],
            "verifier_verdict": "false_positive",
            "proposer_raw": {**fp_unchanged_raw, "reasons": REASONS},
        }
    )
    fp_unchanged = _run(
        result={**fp_unchanged_raw, "reasons": REASONS},
        gate=fp_gate,
        matches=[_match(0.62, "a")],
        ranked=[_cand(0.62, "a")],
        history=HISTORY,
    )
    # step 2 is compared on the model's declared facts: keep what it says equal so only the verdict side differs
    for run in (tp_changed, fp_unchanged):
        assert verdicts.rag_rule_applied(run.gate_result)
    got_tp = _build(tp_changed, read_cards=_cards({}))
    got_fp = _build(fp_unchanged, read_cards=_cards({}))
    assert got_tp == got_fp


def test_a_run_the_rule_applied_to_without_changing_withholds_the_same_things():
    gate = _gate(
        **{
            **APPLIED_GATE,
            "proposed_verdict": "false_positive",
            "rag_rule": {"threshold": 80, "best_pct": 62, "applied": True, "changed": False},
            "steps": {**STEPS, "3r": "applied", "4": "ok", "6": "agree"},
            "flagged_by": [],
        }
    )
    built = _build(_run(gate=gate, matches=[_match(0.62, "a")], ranked=[_cand(0.62, "a")]))
    assert (
        built["reading_attack"] is None
        and built["reading_benign"] is None
        and built["would_change"] is None
    )
    assert all(row["model"] is None and row["match"] is None for row in built["facts"])
    assert "6" not in _rows(built)


def test_no_key_of_what_is_served_names_the_models_verdict_or_confidence():
    built = _build(_applied(), read_cards=_cards({}))
    keys = {k for k in _walk(built) if isinstance(k, str)}
    for name in (
        "suggested_action",
        "confidence",
        "proposed_verdict",
        "proposed_action",
        "verifier_verdict",
        "changed",
        "final_verdict",
    ):
        assert name not in keys, name


def test_a_run_the_rule_did_not_apply_to_serves_everything():
    built = _build(_run())
    assert built["reading_attack"] and built["reading_benign"] and built["would_change"]
    assert all(row["model"] is not None and row["match"] is True for row in built["facts"])
    assert "6" in _rows(built)


@pytest.mark.parametrize("applied", [False, None, "true", 1, "yes"])
def test_only_the_json_true_withholds(applied):
    gate = _gate(rag_rule={"threshold": 80, "best_pct": 62, "applied": applied, "changed": False})
    assert _build(_run(gate=gate))["reading_attack"] == TEXTS["reading_attack"]


# ── it reads, it does not change ────────────────────────────────────────────────────────────────


def test_building_changes_nothing_it_is_given():
    run = _run(history=HISTORY, matches=[_match(0.9, "a")], ranked=[_cand(0.9, "a")])
    before = copy.deepcopy(run)
    _build(run, read_cards=_cards({"a": ("T", "closed_fp")}))
    assert run == before
    applied = _applied()
    before = copy.deepcopy(applied)
    _build(applied)
    assert applied == before


def test_a_second_build_of_the_same_run_is_equal_and_a_new_object():
    run = _run(history=HISTORY)
    first, second = _build(run), _build(run)
    assert first == second and first is not second
    first["checks"].append("x")
    assert _build(run)["checks"] != first["checks"]


# ── follow-up B: tech covers the whole analysis (the proposer row plus its verifier row) ─────────

_NULL_PLAYBOOK = {"name": None, "rule_id": None, "rule_action": None, "rule_table_reviewed": None}


def _tech_of(**cols):
    return _build(_run(**cols))["tech"]


def test_the_figures_are_the_sum_of_the_proposer_row_and_its_verifier_row():
    tech = _tech_of(
        input_tokens=1200,
        output_tokens=340,
        latency_ms=2100,
        cost_usd=decimal.Decimal("0.01234"),
        verifier_input_tokens=300,
        verifier_output_tokens=80,
        verifier_latency_ms=900,
        verifier_cost_usd=decimal.Decimal("0.0021"),
    )
    assert (tech["input_tokens"], tech["output_tokens"], tech["latency_ms"]) == (1500, 420, 3000)
    assert tech["cost_usd"] == 0.01444 and isinstance(tech["cost_usd"], float)
    assert list(tech) == [
        "input_tokens",
        "output_tokens",
        "latency_ms",
        "cost_usd",
        "analysed_at",
        "mitre_ids",
        "correlated_at_analysis",
    ]


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens", "latency_ms"])
@pytest.mark.parametrize(
    ("mine", "theirs", "expected"),
    [
        (5, 7, 12),
        (5, None, 5),
        (None, 7, 7),
        (None, None, None),
        (0, 0, 0),
        (0, None, 0),
        (None, 0, 0),
    ],
)
def test_a_figure_is_none_only_when_both_rows_have_none(field, mine, theirs, expected):
    cols = {"input_tokens": None, "output_tokens": None, "latency_ms": None, "cost_usd": None}
    tech = _tech_of(**{**cols, field: mine, f"verifier_{field}": theirs})
    assert tech[field] == expected
    assert all(tech[other] is None for other in cols if other != field)


@pytest.mark.parametrize(
    ("mine", "theirs", "expected"),
    [
        (decimal.Decimal("0.5"), decimal.Decimal("0.25"), 0.75),
        (decimal.Decimal("0.5"), None, 0.5),
        (None, decimal.Decimal("0.25"), 0.25),
        (None, None, None),
        (decimal.Decimal(0), None, 0.0),
    ],
)
def test_the_cost_follows_the_same_rule(mine, theirs, expected):
    cols = {"input_tokens": None, "output_tokens": None, "latency_ms": None}
    assert _tech_of(**cols, cost_usd=mine, verifier_cost_usd=theirs)["cost_usd"] == expected


@pytest.mark.parametrize("junk", ["12", True, 1.5, [1]])
def test_a_verifier_token_count_that_is_not_an_integer_counts_as_none(junk):
    assert _tech_of(input_tokens=5, verifier_input_tokens=junk)["input_tokens"] == 5
    assert _tech_of(input_tokens=None, verifier_input_tokens=junk)["input_tokens"] is None


@pytest.mark.parametrize("junk", ["12", True, [1], float("nan"), float("inf"), {"a": 1}])
def test_a_verifier_cost_that_is_not_a_finite_number_counts_as_none(junk):
    assert _tech_of(cost_usd=decimal.Decimal("0.5"), verifier_cost_usd=junk)["cost_usd"] == 0.5
    assert _tech_of(cost_usd=None, verifier_cost_usd=junk)["cost_usd"] is None


def test_the_stored_run_has_no_model_column_for_the_verifier_either():
    assert not any("model" in name for name in analysis.StoredRun.__dataclass_fields__)


# ── follow-up C: the playbook says whether its table is signed ──────────────────────────────────


def _table_with(monkeypatch, *, signed):
    real = get_decision_table("brute_force")
    table = dataclasses.replace(
        real,
        reviewed_by="the Owner" if signed else None,
        reviewed_at="2026-11-01" if signed else None,
    )
    monkeypatch.setattr(analysis, "get_decision_table", lambda category: table)
    return table


@pytest.mark.parametrize("signed", [True, False])
def test_the_playbook_carries_the_review_state_of_its_table_today(monkeypatch, signed):
    _table_with(monkeypatch, signed=signed)
    got = _build(_run())["playbook"]
    assert got == {
        "name": "brute_force_v1",
        "rule_id": "bf-2",
        "rule_action": "true_positive",
        "rule_table_reviewed": signed,
    }
    assert isinstance(got["rule_table_reviewed"], bool)


def test_a_table_with_no_matching_rule_still_says_whether_it_is_signed(monkeypatch):
    _table_with(monkeypatch, signed=False)
    facts = {
        **FACTS,
        "severity": "critical",
        "rule_level": 3,
        "ioc_reputation": "clean",
        "asset_criticality": "high",
    }
    got = _build(_run(gate=_gate(facts=facts)))["playbook"]
    assert (got["rule_id"], got["rule_table_reviewed"]) == (None, False)


def test_no_table_gives_none_for_the_review_state():
    got = _build(_run(gate=_gate(facts={**FACTS, "category": "unknown"})))["playbook"]
    assert got["rule_table_reviewed"] is None


# ── follow-up D: the reasons are capped like the suggestion's ───────────────────────────────────


def _many(n):
    return [{"claim": f"c{i}", "quote": f"q{i}", "source": "context"} for i in range(n)]


def test_the_cap_is_ten_like_suggestion_reasons():
    assert analysis.REASONS_SHOWN == 10
    result = {**RAW, "reasons": _many(13)}
    suggestion = queue._suggestion_of("r", result, _gate(), NOW)
    assert len(suggestion.reasons) == analysis.REASONS_SHOWN


def test_thirteen_reasons_serve_the_first_ten_with_their_flags():
    raw = {**RAW, "reasons": _many(13)}
    gate = _gate(
        proposer_raw=raw,
        dropped_reasons=[{"index": 3, "why": "empty_quote"}, {"index": 11, "why": "not_substring"}],
    )
    rows = _build(_run(result={**raw, "reasons": _many(10)}, gate=gate))["reasons"]
    assert [r["claim"] for r in rows] == [f"c{i}" for i in range(10)]
    assert [r["verified"] for r in rows] == [i != 3 for i in range(10)]
    assert rows[3]["why"] == "empty_quote"


def test_the_stored_survivors_are_capped_too_when_the_raw_reasons_are_gone():
    result = {**RAW, "reasons": _many(13)}
    rows = _build(_run(result=result, gate=_gate(proposer_raw=None)))["reasons"]
    assert len(rows) == 10


def test_the_cap_counts_the_first_ten_items_as_the_suggestion_does():
    """`suggestion.reasons` takes the first ten items and then drops what is not an object: so does the analysis."""
    raw = {**RAW, "reasons": ["junk", None, *_many(12)]}
    rows = _build(_run(result=raw, gate=_gate(proposer_raw=raw)))["reasons"]
    assert [r["claim"] for r in rows] == [f"c{i}" for i in range(8)]
    suggestion = queue._suggestion_of("r", {**RAW, "reasons": raw["reasons"]}, _gate(), NOW)
    assert [r["claim"] for r in suggestion.reasons] == [r["claim"] for r in rows]


def test_ten_or_fewer_are_all_served():
    for n in (0, 1, 10):
        raw = {**RAW, "reasons": _many(n)}
        assert len(_build(_run(result=raw, gate=_gate(proposer_raw=raw)))["reasons"]) == n


# ── follow-up E: a decision table that cannot be read or applied never breaks the view ──────────


def _boom(exc):
    def reader(category):
        raise exc

    return reader


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("boom"),
        KeyError("k"),
        AttributeError("a"),
        IndexError("i"),
        ZeroDivisionError(),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"),
        OSError("disk"),
        TypeError("t"),
        ValueError("v"),
        NotImplementedError("n"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_a_decision_table_reader_that_raises_anything_gives_the_all_null_playbook(monkeypatch, exc):
    monkeypatch.setattr(analysis, "get_decision_table", _boom(exc))
    built = _build(_run())
    assert built["playbook"] == _NULL_PLAYBOOK
    assert built["summary"] == TEXTS["summary"] and len(built["checks"]) == 6  # the rest is intact


def test_applying_a_table_that_raises_gives_the_all_null_playbook(monkeypatch):
    def apply(table, facts):
        raise RuntimeError("boom")

    monkeypatch.setattr(analysis, "apply_table", apply)
    assert _build(_run())["playbook"] == _NULL_PLAYBOOK


def test_a_table_whose_review_state_cannot_be_read_gives_the_all_null_playbook(monkeypatch):
    class Odd:
        playbook = "x"
        rules = ()

        @property
        def reviewed(self):
            raise RuntimeError("boom")

    monkeypatch.setattr(analysis, "get_decision_table", lambda category: Odd())
    monkeypatch.setattr(analysis, "apply_table", lambda table, facts: None)
    assert _build(_run())["playbook"] == _NULL_PLAYBOOK


def _kb_tree(tmp_path, table_text, playbook_text="# `brute_force` `brute_force_v1`\n"):
    (tmp_path / "decision_tables").mkdir()
    (tmp_path / "playbooks").mkdir()
    (tmp_path / "decision_tables" / "brute_force.yaml").write_text(table_text, "utf-8")
    (tmp_path / "playbooks" / "brute_force.md").write_text(playbook_text, "utf-8")
    real = analysis.get_decision_table
    return lambda category: real(category, root=tmp_path)


def test_a_rules_value_that_is_not_a_list_raises_a_plain_type_error_in_the_reader_and_not_in_the_view(
    monkeypatch, tmp_path
):
    """The reviewer's case: `rules: 5` makes `kb.lookup.get_decision_table` raise a plain `TypeError`, not its own
    `DecisionTableError`. The view must not."""
    reader = _kb_tree(tmp_path, "category: brute_force\nplaybook: brute_force_v1\nrules: 5\n")
    with pytest.raises(TypeError):
        reader("brute_force")
    monkeypatch.setattr(analysis, "get_decision_table", reader)
    assert _build(_run())["playbook"] == _NULL_PLAYBOOK


def test_an_empty_playbook_file_raises_in_the_reader_and_not_in_the_view(monkeypatch, tmp_path):
    reader = _kb_tree(tmp_path, "category: brute_force\nplaybook: x\nrules: []\n", playbook_text="")
    with pytest.raises(IndexError):
        reader("brute_force")
    monkeypatch.setattr(analysis, "get_decision_table", reader)
    assert _build(_run())["playbook"] == _NULL_PLAYBOOK


@pytest.mark.parametrize(
    "table_text",
    [
        "category: [unclosed\n",
        "- a\n- b\n",
        "",
        "category: brute_force\nplaybook: brute_force_v1\nrules: oops\n",
    ],
    ids=["yaml_syntax", "top_level_list", "empty", "rules_is_a_string"],
)
def test_other_malformed_tables_give_the_all_null_playbook(monkeypatch, tmp_path, table_text):
    reader = _kb_tree(tmp_path, table_text)
    monkeypatch.setattr(analysis, "get_decision_table", reader)
    assert _build(_run())["playbook"] == _NULL_PLAYBOOK


def test_the_failure_is_logged_by_type_and_category_only(monkeypatch, caplog):
    monkeypatch.setattr(analysis, "get_decision_table", _boom(RuntimeError("SECRET-PATH-OR-TEXT")))
    with caplog.at_level("WARNING", logger=analysis.logger.name):
        _build(_run())
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "RuntimeError" in messages and "brute_force" in messages
    assert "SECRET-PATH-OR-TEXT" not in messages
