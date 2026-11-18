"""`tier1.triage` and the two-sided RAG rule (DEC-219, as changed by DEC-225 / RR-T3; specs
`docs/superpowers/specs/2026-11-15-rag-low-match-fp-rule-design.md` and the Owner's rule of 18/11): what the run
computes (the single top knowledge item: its percentage, its side and how the percentage was made), what the gate
is handed, what the verifier is sent, and what is stored. NO DATABASE.

`run_triage_job` and `evaluate_alert` are the real code; what touches the database is replaced by recorders (the
alert read, the correlation read, the idle-timeout statement, `llm_runs.write_run`, `_set_triage_status`,
`write_event`) and by three stubs for the RAG: the lookup's status and material (`lookup_failure`,
`lookup_material`), the stored `matches` and `ranked` of the lookup the prompt held (`_lookup_scored`) and the
conclusions of the entries (`_entry_conclusions`). The database-backed counterpart, which stores real rows and reads
them back through the alert page's own statement, is `test_rag_rule_db.py` (marked `db`; it cannot run on a host
whose `TEST_DATABASE_URL` does not authenticate).

The central claim of the card: `best_pct` is the number the alert page shows for the same stored run. The page
reads the `matches` and `ranked` of the lookup the run's row names and the run's `citation_warnings` through
`llm.rag_view.rag_view` (`tier1.queue.latest_suggestion_rag`); the job reads the same things through the same
function, so the tests below feed ONE stored run to both and compare.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.infra import config
from app.infra.jobs import Job
from app.llm.builder import KbLearnedLevel
from app.llm.rag_view import best_pct as page_best_pct
from app.rag.lookup import PromptMaterial
from app.tier1 import queue
from app.tier1 import triage as triage_module
from app.tier1.triage import EvalSwitches, evaluate_alert, run_triage_job

from tests.fakes.llm import TRIAGE_V4_FALSE_POSITIVE, TRIAGE_V4_TRUE_POSITIVE, VERIFIER_V2_AGREE
from tests.test_tier1_json_schema import _ALERT_ID, _Model, _row

TP, FP = "true_positive", "false_positive"
LOOKUP_ID = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
ENTRY_UUID = uuid.UUID("00000000-0000-0000-0000-0000000000e1")
ENTRY_TEXT = "# Máy quét nội bộ\n\nCảnh báo quét cổng từ máy quản trị đã được đóng là lành tính."
HISTORY = (
    "level: 1\nkey_name: rule_id\ntotal: 4\n"
    "by_conclusion: tier1_closed_fp=3, tier1_closed_benign=1, escalated_open=0, concluded_fp=0, "
    "concluded_policy_violation=0, confirmed_incident=0\nlast_seen: 2026-08-10\nexamples: 1786903000.1"
)


def _match(score, entry="e-1"):
    return {"entry_id": entry, "level": "giong", "content_sha256": "a" * 64, "score": score}


def _material(pct=62, *, history=HISTORY, entries=True):
    found = ((KbLearnedLevel.GIONG, pct, ENTRY_TEXT),) if entries else ()
    return PromptMaterial(LOOKUP_ID, history, found)


class _Conn:
    """The connection the helper may not touch: any use of it fails the test."""

    def __getattr__(self, name):
        raise AssertionError(f"the connection was used: {name}")


@pytest.fixture
def world(monkeypatch):
    """No database: the reads return the canonical alert and the stubs below, the writes are recorded."""
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    monkeypatch.delenv("LLM_RESPONSE_FORMAT", raising=False)
    monkeypatch.setenv("RAG_ENABLED", "true")
    monkeypatch.setenv("TRIAGE_RAG_FP_BELOW_PCT", "80")
    writes = SimpleNamespace(
        runs=[],
        statuses=[],
        events=[],
        failure=None,
        material=_material(62),
        matches=[_match(0.62)],
        ranked=None,
        # the conclusion of each entry by id; an entry not listed is an incident (the side the rule reads first)
        conclusions={},
        material_reads=0,
        match_reads=[],
        conclusion_reads=[],
    )

    def _write_run(_conn, **kwargs):
        writes.runs.append(kwargs)
        return kwargs["run_id"]

    def _lookup_material(_conn, _subject, **_kw):
        writes.material_reads += 1
        return writes.material

    def _lookup_scored(_conn, lookup_id):
        writes.match_reads.append(lookup_id)
        return writes.matches, writes.ranked

    def _entry_conclusions(_conn, entry_ids):
        writes.conclusion_reads.append(list(entry_ids))
        found = {}
        for entry_id in entry_ids:
            conclusion = writes.conclusions.get(entry_id, "confirmed_incident")
            if conclusion is not None:  # `None` in the table: the entry's row is gone
                found[entry_id] = conclusion
        return found

    monkeypatch.setattr(triage_module, "_raise_idle_timeout", lambda conn, cfg: None)
    monkeypatch.setattr(triage_module, "_load", lambda conn, alert_id: _row())
    monkeypatch.setattr(
        triage_module.correlation,
        "summarize_for_prompt",
        lambda conn, subject, **kw: triage_module.correlation.CorrelationSummary(
            rows=(), samples=()
        ),
    )
    monkeypatch.setattr(triage_module.llm_runs, "write_run", _write_run)
    monkeypatch.setattr(
        triage_module,
        "_set_triage_status",
        lambda conn, alert_id, status: writes.statuses.append(status),
    )
    monkeypatch.setattr(triage_module, "write_event", lambda *a, **k: writes.events.append((a, k)))
    monkeypatch.setattr(triage_module, "lookup_failure", lambda conn, subject: writes.failure)
    monkeypatch.setattr(triage_module, "lookup_material", _lookup_material)
    monkeypatch.setattr(triage_module, "_lookup_scored", _lookup_scored)
    monkeypatch.setattr(triage_module, "_entry_conclusions", _entry_conclusions)

    def run(model, **env) -> SimpleNamespace:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        run_triage_job(
            None, Job(job_id=1, job_type="triage", subject_id=_ALERT_ID, attempts=1), adapter=model
        )
        writes.proposer = next(r for r in writes.runs if r["role"] == "proposer")
        writes.verifier = next((r for r in writes.runs if r["role"] == "verifier"), None)
        writes.event_types = [a[1] for a, _k in writes.events]
        return writes

    writes.run = run
    writes.setenv = monkeypatch.setenv
    return writes


def _tp_model(verifier=VERIFIER_V2_AGREE):
    return _Model([TRIAGE_V4_TRUE_POSITIVE, verifier])


def _without_nonce(text: str) -> str:
    """A prompt with its per-build nonce blanked, so two builds of the same alert compare equal."""
    return re.sub(r'nonce="[0-9a-f]+"', 'nonce="N"', text)


def _event(writes, event_type):
    return next(k["payload"] for a, k in writes.events if a[1] == event_type)


# ---------------------------------------------------------------------------------------------------
# the rule at work, through the job (spec 4, 5)
# ---------------------------------------------------------------------------------------------------


class TestAnIncidentMatchBelowTheThreshold:
    def test_a_true_positive_is_stored_as_false_positive_beside_the_models_answer(self, world):
        world.run(_tp_model())

        row = world.proposer
        assert row["result"]["suggested_action"] == FP  # what ① ended with, what Tier 1 is served
        gate_result = row["gate_result"]
        assert gate_result["version"] == 2
        assert gate_result["proposed_verdict"] == TP  # the model's own answer
        assert gate_result["final_verdict"] == FP
        # the rule is not a gate force: the record is `rag_rule`
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": 62,
            "applied": True,
            "changed": True,
            "entry_side": "incident",
            "rule_verdict": FP,
            "basis": "match",
        }
        assert gate_result["steps"]["3r"] == "changed"
        assert (
            gate_result["proposer_raw"]["suggested_action"] == TP
        )  # the model's JSON is as it came
        assert row["rag_lookup_id"] == LOOKUP_ID
        assert world.statuses == ["ready"]

    def test_the_confidence_and_the_reasons_are_the_models(self, world):
        world.run(_tp_model())

        result = world.proposer["result"]
        assert result["confidence"] == TRIAGE_V4_TRUE_POSITIVE["confidence"]
        assert result["reasons"] == TRIAGE_V4_TRUE_POSITIVE["reasons"]

    def test_step_4_evaluated_the_false_positive_the_rule_produced(self, world):
        world.run(_tp_model())

        gate_result = world.proposer["gate_result"]
        assert gate_result["steps"]["4"] == "missing"  # a critical alert: severity is not met
        assert "severity" in gate_result["missing"]
        assert "step4" in gate_result["flagged_by"]
        assert "rag_rule" not in gate_result["flagged_by"]  # a rule is not a failed check

    def test_llm_gate_forced_is_never_written_and_triage_suggested_says_the_verdict_after_the_rule(
        self, world
    ):
        world.run(_tp_model())

        assert world.event_types == [
            "triage.suggested"
        ]  # nothing is forced: the event is never written
        suggested = _event(world, "triage.suggested")
        assert set(suggested) == {
            "suggested_action",
            "confidence",
            "forced",
            "flagged_by",
            "run_id",
        }
        assert suggested["suggested_action"] == FP  # the verdict after the rule
        assert suggested["forced"] is False
        assert suggested["flagged_by"] == world.proposer["gate_result"]["flagged_by"]

    def test_the_verifier_is_sent_the_models_verdict_and_step_6_compares_with_it(self, world):
        model = (
            _tp_model()
        )  # the verifier answers true_positive and agrees: it was asked about that

        world.run(model)

        sent = model.requests[1]["user"]
        assert '"verdict": "true_positive"' in sent
        assert '"verdict": "false_positive"' not in sent
        assert world.verifier["user_message"] == sent
        assert world.verifier["gate_result"]["compared_to"] == TP
        assert world.verifier["gate_result"]["step6"] == "agree"
        assert "step6" not in world.proposer["gate_result"]["flagged_by"]
        assert world.proposer["gate_result"]["verifier_verdict"] == TP

    def test_a_verifier_that_answers_the_rules_verdict_disagrees(self, world):
        answers_fp = {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}

        world.run(_tp_model(answers_fp))

        assert world.verifier["gate_result"]["step6"] == "disagree"
        assert "step6" in world.proposer["gate_result"]["flagged_by"]
        assert (
            world.proposer["result"]["suggested_action"] == FP
        )  # a flag never changes the verdict

    def test_the_proposers_prompt_and_the_calls_are_what_they_would_be_without_the_rule(
        self, world
    ):
        with_rule = _tp_model()
        world.run(with_rule)
        prompt_with = _without_nonce(world.proposer["user_message"])

        world.runs.clear()
        without = _tp_model()
        world.run(without, TRIAGE_RAG_FP_BELOW_PCT="0")

        # the rule is after the model, not in the prompt: the same user message (the nonce is drawn per build)
        assert _without_nonce(world.proposer["user_message"]) == prompt_with
        assert with_rule.requests[0]["system"] == without.requests[0]["system"]
        assert len(with_rule.requests) == len(without.requests) == 2


class TestARuleThatAppliedButChangedNothing:
    def test_a_false_positive_answer_is_applied_and_not_forced(self, world):
        model = _Model(
            [TRIAGE_V4_FALSE_POSITIVE, {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}]
        )

        world.run(model)

        gate_result = world.proposer["gate_result"]
        assert world.proposer["result"]["suggested_action"] == FP
        assert gate_result["proposed_verdict"] == gate_result["final_verdict"] == FP
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": 62,
            "applied": True,
            "changed": False,
            "entry_side": "incident",
            "rule_verdict": FP,
            "basis": "match",
        }
        assert gate_result["steps"]["3r"] == "applied"
        assert world.event_types == ["triage.suggested"]  # llm.gate_forced is never written
        assert _event(world, "triage.suggested")["forced"] is False

    @pytest.mark.parametrize("score, pct", [(0.80, 80), (0.81, 81), (0.95, 95), (1.0, 100)])
    def test_an_incident_at_or_above_the_threshold_with_a_model_true_positive(
        self, world, score, pct
    ):
        world.matches = [_match(score)]
        world.material = _material(pct)

        world.run(_tp_model())

        gate_result = world.proposer["gate_result"]
        assert world.proposer["result"]["suggested_action"] == TP
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": pct,
            "applied": True,
            "changed": False,
            "entry_side": "incident",
            "rule_verdict": TP,
            "basis": "match",
        }
        assert gate_result["steps"]["3r"] == "applied"
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert world.event_types == ["triage.suggested"]


class TestAnIncidentAtOrAboveTheThresholdIsATruePositive:
    """The new direction of the rule (DEC-225): the model said `false_positive`, the top knowledge item is a
    confirmed incident that matched at or over the threshold."""

    @pytest.mark.parametrize("score, pct", [(0.80, 80), (0.85, 85), (1.0, 100)])
    def test_a_model_false_positive_is_stored_as_true_positive_beside_the_models_answer(
        self, world, score, pct
    ):
        world.matches = [_match(score)]
        world.material = _material(pct)
        model = _Model(
            [TRIAGE_V4_FALSE_POSITIVE, {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}]
        )

        world.run(model)

        row = world.proposer
        assert row["result"]["suggested_action"] == TP  # what ① ended with
        gate_result = row["gate_result"]
        assert gate_result["proposed_verdict"] == FP  # the model's own answer
        assert gate_result["final_verdict"] == TP
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": pct,
            "applied": True,
            "changed": True,
            "entry_side": "incident",
            "rule_verdict": TP,
            "basis": "match",
        }
        assert gate_result["steps"]["3r"] == "changed"
        assert (
            gate_result["proposer_raw"]["suggested_action"] == FP
        )  # the model's JSON is as it came
        assert world.event_types == ["triage.suggested"]  # nothing is forced
        assert _event(world, "triage.suggested")["suggested_action"] == TP

    def test_step_4_is_n_a_for_a_true_positive_the_rule_produced(self, world):
        world.matches = [_match(0.85)]
        model = _Model(
            [TRIAGE_V4_FALSE_POSITIVE, {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}]
        )

        world.run(model)

        gate_result = world.proposer["gate_result"]
        assert gate_result["steps"]["4"] == "n/a" and gate_result["missing"] == []
        assert "step4" not in gate_result["flagged_by"]

    def test_the_verifier_is_sent_the_models_false_positive_and_step_6_compares_with_it(
        self, world
    ):
        world.matches = [_match(0.85)]
        model = _Model(
            [TRIAGE_V4_FALSE_POSITIVE, {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}]
        )

        world.run(model)

        sent = model.requests[1]["user"]
        assert '"verdict": "false_positive"' in sent and '"verdict": "true_positive"' not in sent
        assert world.verifier["gate_result"]["compared_to"] == FP
        assert world.verifier["gate_result"]["step6"] == "agree"
        assert "step6" not in world.proposer["gate_result"]["flagged_by"]
        assert world.proposer["result"]["suggested_action"] == TP


class TestABenignItem:
    @pytest.mark.parametrize(
        "conclusion",
        ["closed_fp", "closed_benign", "concluded_fp", "concluded_policy_violation"],
    )
    def test_at_or_above_the_threshold_a_model_true_positive_is_stored_as_false_positive(
        self, world, conclusion
    ):
        world.matches = [_match(0.89)]
        world.material = _material(89)
        world.conclusions = {"e-1": conclusion}

        world.run(_tp_model())

        row = world.proposer
        assert row["result"]["suggested_action"] == FP
        gate_result = row["gate_result"]
        assert gate_result["proposed_verdict"] == TP and gate_result["final_verdict"] == FP
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": 89,
            "applied": True,
            "changed": True,
            "entry_side": "benign",
            "rule_verdict": FP,
            "basis": "match",
        }
        assert gate_result["steps"]["3r"] == "changed"
        assert gate_result["forced"] is False and gate_result["forced_by"] == []

    def test_under_the_threshold_the_rule_is_not_applied_and_the_models_true_positive_stands(
        self, world
    ):
        world.matches = [_match(0.62)]
        world.conclusions = {"e-1": "closed_benign"}

        world.run(_tp_model())

        gate_result = world.proposer["gate_result"]
        assert world.proposer["result"]["suggested_action"] == TP
        assert gate_result["proposed_verdict"] == gate_result["final_verdict"] == TP
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": 62,
            "applied": False,
            "changed": False,
            "entry_side": "benign",
            "rule_verdict": None,
            "basis": "match",
        }
        assert gate_result["steps"]["3r"] == "n/a"
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert world.event_types == ["triage.suggested"]

    def test_the_conclusion_is_read_whatever_the_entrys_status(self, world):
        """The entry is read by id and its `conclusion` is the side, not its `status` (a retired entry is read the
        same): the stub answers for any id, as `rag.entries.entry_cards` does."""
        world.matches = [_match(0.9)]
        world.conclusions = {"e-1": "closed_fp"}

        world.run(_tp_model())

        assert world.conclusion_reads == [["e-1"]]
        assert world.proposer["gate_result"]["rag_rule"]["entry_side"] == "benign"


class TestTheTopItemIsTheOneThatDecides:
    def test_the_highest_scoring_match_decides_not_the_first_or_the_lowest(self, world):
        world.matches = [_match(0.55, "e-1"), _match(0.91, "e-2"), _match(0.62, "e-3")]
        world.conclusions = {
            "e-1": "confirmed_incident",
            "e-2": "closed_fp",
            "e-3": "confirmed_incident",
        }

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"], rule["basis"]) == (91, "benign", "match")
        assert rule["applied"] is True and rule["rule_verdict"] == FP
        assert world.proposer["result"]["suggested_action"] == FP
        assert world.conclusion_reads == [["e-2"]]  # one item: the top one

    def test_two_entries_tied_on_the_top_score_with_opposite_sides_the_incident_wins(self, world):
        world.matches = [_match(0.85, "e-1"), _match(0.85, "e-2"), _match(0.5, "e-3")]
        world.conclusions = {"e-1": "closed_fp", "e-2": "confirmed_incident"}
        model = _Model(
            [TRIAGE_V4_FALSE_POSITIVE, {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}]
        )

        world.run(model)

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"], rule["rule_verdict"]) == (85, "incident", TP)
        assert world.proposer["result"]["suggested_action"] == TP

    def test_a_tie_between_benign_entries_is_benign(self, world):
        world.matches = [_match(0.85, "e-1"), _match(0.85, "e-2")]
        world.conclusions = {"e-1": "closed_fp", "e-2": "concluded_policy_violation"}

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["entry_side"], rule["rule_verdict"]) == ("benign", FP)

    def test_a_tie_with_an_unreadable_entry_and_no_incident_is_no_side(self, world):
        """The unreadable entry could be the incident: the rule does not guess."""
        world.matches = [_match(0.85, "e-1"), _match(0.85, "e-2")]
        world.conclusions = {"e-1": "closed_fp", "e-2": None}  # e-2's row is gone

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"], rule["applied"]) == (85, None, False)
        assert world.proposer["result"]["suggested_action"] == TP

    def test_a_tie_with_an_unreadable_entry_and_an_incident_is_the_incident(self, world):
        world.matches = [_match(0.85, "e-1"), _match(0.85, "e-2")]
        world.conclusions = {"e-1": "confirmed_incident", "e-2": None}
        model = _Model(
            [TRIAGE_V4_FALSE_POSITIVE, {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}]
        )

        world.run(model)

        assert world.proposer["gate_result"]["rag_rule"]["entry_side"] == "incident"
        assert world.proposer["result"]["suggested_action"] == TP

    @pytest.mark.parametrize("conclusion", [None, "", "closed", "something_else", 7])
    def test_an_entry_that_is_gone_or_has_no_known_conclusion_gives_no_side(
        self, world, conclusion
    ):
        world.matches = [_match(0.62)]
        world.conclusions = {"e-1": conclusion}

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"], rule["applied"]) == (62, None, False)
        assert rule["rule_verdict"] is None and rule["basis"] == "match"
        assert world.proposer["result"]["suggested_action"] == TP
        assert world.proposer["gate_result"]["steps"]["3r"] == "n/a"


class TestARuleThatDoesNotApply:
    def test_the_switch_off_leaves_it_whatever_the_match_and_reads_nothing_more(self, world):
        world.run(_tp_model(), TRIAGE_RAG_FP_BELOW_PCT="0")

        gate_result = world.proposer["gate_result"]
        assert world.proposer["result"]["suggested_action"] == TP
        assert gate_result["rag_rule"] == {
            "threshold": 0,
            "best_pct": None,
            "applied": False,
            "changed": False,
            "entry_side": None,
            "rule_verdict": None,
            "basis": None,
        }
        assert gate_result["steps"]["3r"] == "n/a"
        # not one statement more than before the key existed
        assert world.match_reads == [] and world.conclusion_reads == []
        assert world.event_types == ["triage.suggested"]

    def test_with_the_switch_unset_it_is_the_same_as_zero(self, world, monkeypatch):
        monkeypatch.delenv("TRIAGE_RAG_FP_BELOW_PCT", raising=False)

        world.run(_tp_model())

        assert world.proposer["gate_result"]["rag_rule"]["threshold"] == 0
        assert world.proposer["result"]["suggested_action"] == TP
        assert world.match_reads == [] and world.conclusion_reads == []


class TestWithTheSwitchOffARunIsWhatItWasPlusTheRagRuleKey:
    """Spec 7: the stored rows of a run with `TRIAGE_RAG_FP_BELOW_PCT=0` are what they are today, plus
    `gate_result.rag_rule` (and `steps["3r"] == "n/a"`)."""

    def test_the_stored_proposer_row(self, world):
        world.run(_tp_model(), TRIAGE_RAG_FP_BELOW_PCT="0")

        row = world.proposer
        assert row["result"]["suggested_action"] == TP and row["stopped_by"] is None
        gate_result = row["gate_result"]
        assert set(gate_result) == {
            "version",
            "proposed_verdict",
            "final_verdict",
            "forced",
            "forced_by",
            "flagged_by",
            "rag_rule",
            "step1_errors",
            "steps",
            "hallucination_flag",
            "mismatched_fields",
            "dropped_reasons",
            "missing",
            "facts",
            "warnings",
            "verifier_verdict",
            "playbook_used_effective",
            "prompt_version",
            "proposer_raw",
        }
        assert gate_result["rag_rule"] == {
            "threshold": 0,
            "best_pct": None,
            "applied": False,
            "changed": False,
            "entry_side": None,
            "rule_verdict": None,
            "basis": None,
        }
        assert gate_result["proposed_verdict"] == gate_result["final_verdict"] == TP
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert gate_result["flagged_by"] == [] and gate_result["missing"] == []
        assert list(gate_result["steps"]) == ["1", "2", "3", "3r", "4", "5", "6", "7"]
        assert gate_result["steps"]["3r"] == "n/a" and gate_result["steps"]["4"] == "n/a"

    def test_the_verifier_row_and_the_events(self, world):
        model = _tp_model()
        world.run(model, TRIAGE_RAG_FP_BELOW_PCT="0")

        assert set(world.verifier["gate_result"]) == {
            "role",
            "step6",
            "compared_to",
            "proposer_run_id",
        }
        assert world.verifier["gate_result"]["compared_to"] == TP
        assert '"verdict": "true_positive"' in model.requests[1]["user"]
        assert world.event_types == ["triage.suggested"]
        suggested = _event(world, "triage.suggested")
        assert suggested["forced"] is False and suggested["flagged_by"] == []
        assert suggested["suggested_action"] == TP


# ---------------------------------------------------------------------------------------------------
# best_pct is None where the page shows no number (spec 2); and then there is no side to read
# ---------------------------------------------------------------------------------------------------


class TestNoNumberNoRule:
    def _assert_the_models_verdict_stays(self, world):
        gate_result = world.proposer["gate_result"]
        assert world.proposer["result"]["suggested_action"] == TP
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": None,
            "applied": False,
            "changed": False,
            "entry_side": None,
            "rule_verdict": None,
            "basis": None,
        }
        assert gate_result["steps"]["3r"] == "n/a"
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert "llm.gate_forced" not in world.event_types
        assert world.conclusion_reads == []  # no number: no entry was read

    def test_rag_off(self, world):
        world.run(_tp_model(), RAG_ENABLED="false")

        self._assert_the_models_verdict_stays(world)
        assert world.material_reads == 0 and world.match_reads == []
        assert world.proposer["rag_lookup_id"] is None

    def test_no_lookup(self, world):
        world.material = None

        world.run(_tp_model())

        self._assert_the_models_verdict_stays(world)
        assert world.match_reads == []

    def test_a_failed_lookup(self, world):
        world.failure = (
            "auth"  # `rag_not_applied:auth`: no section, and `lookup_material` is not read
        )

        world.run(_tp_model())

        self._assert_the_models_verdict_stays(world)
        assert "rag_not_applied:auth" in world.proposer["citation_warnings"]
        assert world.match_reads == [] and world.material_reads == 0

    def test_a_lookup_that_kept_no_match(self, world):
        world.material = _material(entries=False)  # history only: the section is in the prompt
        world.matches = []

        world.run(_tp_model())

        self._assert_the_models_verdict_stays(world)
        assert world.proposer["rag_lookup_id"] == LOOKUP_ID  # the prompt held it; it has no number

    def test_a_lookup_row_with_no_stored_matches_at_all(self, world):
        world.material = _material(entries=False)
        world.matches = None

        world.run(_tp_model())

        self._assert_the_models_verdict_stays(world)

    def test_a_lookup_row_that_is_gone(self, world):
        world.matches = None  # `_lookup_scored` answers None for a missing or an unreadable row

        world.run(_tp_model())

        self._assert_the_models_verdict_stays(world)

    def test_the_token_budget_dropped_the_learned_section(self, world):
        """A budget so small that every cut is taken: the entries go first (`learned_entries_dropped`), the
        history next. The run holds no lookup then (`rag_lookup_id` is None: the short-circuit branch); the page
        shows no number, and neither does the rule, whatever the stored matches say."""
        world.run(_tp_model(), PROMPT_TOTAL_BUDGET_TOKENS="1")

        self._assert_the_models_verdict_stays(world)
        assert "learned_entries_dropped" in world.proposer["citation_warnings"]
        assert world.proposer["rag_lookup_id"] is None and world.match_reads == []

    def test_the_token_budget_dropped_the_entries_and_kept_the_history(self, world):
        """The other branch: a budget one token under the full prompt takes only the first cut, the entries
        (`learned_entries_dropped`). The history stays, so the run still names its lookup
        (`rag_lookup_id` is set), the job READS that lookup's stored matches (a 62 % match is there) and the
        warning alone gives no number - the page's own rule (`rag_view`), so the page shows none either.
        """
        full = evaluate_alert(
            None,
            _ALERT_ID,
            adapter=_tp_model(),
            cfg=config.load(),
            switches=EvalSwitches(rag=True),
        )
        # that evaluation read the lookup (and the top entry) once; this is about the job below
        world.match_reads.clear()
        world.conclusion_reads.clear()

        world.run(_tp_model(), PROMPT_TOTAL_BUDGET_TOKENS=str(full.built.estimated_tokens - 1))

        warnings = world.proposer["citation_warnings"]
        assert "learned_entries_dropped" in warnings and "learned_history_dropped" not in warnings
        assert world.proposer["rag_lookup_id"] == LOOKUP_ID  # the history is in the prompt
        assert "key_name: rule_id" in world.proposer["user_message"]
        assert ENTRY_TEXT not in world.proposer["user_message"]
        assert world.match_reads == [LOOKUP_ID]  # it read the matches, and the warning decided
        assert world.matches == [_match(0.62)]  # ... which held a 62 % match
        self._assert_the_models_verdict_stays(world)
        assert (
            _what_the_page_shows(
                result=world.proposer["result"],
                gate_result=world.proposer["gate_result"],
                warnings=warnings,
                matches=world.matches,
            )
            is None
        )

    def test_a_response_with_no_lookup_in_the_prompt_reads_no_matches(self, world):
        world.material = _material(entries=False, history=None)  # "nothing found": no number either
        world.matches = []

        world.run(_tp_model())

        self._assert_the_models_verdict_stays(world)


# ---------------------------------------------------------------------------------------------------
# best_pct IS THE PAGE'S NUMBER (the hard rule of the card)
# ---------------------------------------------------------------------------------------------------


class _PageConn:
    """What `queue.latest_suggestion_rag` needs of a connection: the newest proposer row, as
    `_SUGGESTION_SQL` selects it. The statement itself is the database tests'."""

    def __init__(self, row):
        self._row = row

    def execute(self, _statement, _params=None):
        return SimpleNamespace(fetchone=lambda: self._row)


def _what_the_page_shows(*, result, gate_result, warnings, matches) -> int | None:
    """`rag.best_pct` of the alert view for a stored run: the page's reader, over a row shaped as its
    statement returns it."""
    row = (
        "run-1",
        result,
        gate_result,
        datetime(2026, 11, 15, tzinfo=UTC),
        warnings,
        matches,
        None,  # ranked
        None,  # history
        None,  # input_tokens
        None,  # output_tokens
        None,  # latency_ms
        None,  # cost_usd
        None,  # the verifier row's four sums: input_tokens, output_tokens, latency_ms, cost_usd
        None,
        None,
        None,
    )
    return queue.latest_suggestion_rag(_PageConn(row), _ALERT_ID)[3]["best_pct"]


class TestTheNumberIsTheOneThePageShows:
    @pytest.mark.parametrize(
        "matches",
        [
            [_match(0.62)],
            [_match(0.55), _match(0.91), _match(0.62)],
            [_match(0.625)],  # 62.5: the same rounding as the page
            [_match(0.795), _match(0.5)],
            [_match(0.0)],
            [_match(1.0)],
            [
                {"entry_id": "e", "level": "giong", "content_sha256": "a" * 64}
            ],  # a match with no score
            [_match(True)],  # a bool is not a score
            [_match("0.9")],
            [_match(float("nan"))],
            [_match(1.5), _match(-0.2)],  # outside [0, 1]
            [_match(1.5), _match(0.7)],
            ["not a match", None, 3, _match(0.66)],
            [],
            None,
            {"not": "a list"},
        ],
    )
    def test_for_the_same_stored_run_the_gate_and_the_page_read_the_same_number(
        self, world, matches
    ):
        world.matches = matches

        world.run(_tp_model())

        gate_best = world.proposer["gate_result"]["rag_rule"]["best_pct"]
        page_best = _what_the_page_shows(
            result=world.proposer["result"],
            gate_result=world.proposer["gate_result"],
            warnings=world.proposer["citation_warnings"],
            matches=world.matches,
        )
        assert gate_best == page_best
        # the default top item is an incident, which the rule applies to on either side of the threshold: it applies
        # exactly when there is a number
        assert world.proposer["gate_result"]["rag_rule"]["applied"] is (gate_best is not None)

    @pytest.mark.parametrize(
        "warnings", [["learned_entries_dropped"], ["x", "learned_entries_dropped"]]
    )
    @pytest.mark.parametrize("matches", [[_match(0.62)], [_match(0.9)], [], None])
    def test_the_entries_dropped_warning_gives_no_number_to_both(
        self, monkeypatch, matches, warnings
    ):
        job = _top(monkeypatch, matches, warnings=warnings)
        page = _what_the_page_shows(
            result={"suggested_action": TP},
            gate_result={},
            warnings=warnings,
            matches=matches,
        )
        assert job == triage_module.RagTop(None, None, None) and page is None

    @pytest.mark.parametrize(
        "matches", [[_match(0.62)], [_match(0.9)], [_match(0.5), _match(0.71)]]
    )
    def test_without_the_warning_both_give_the_best_of_the_stored_matches(
        self, monkeypatch, matches
    ):
        job = _top(monkeypatch, matches, warnings=["no_table:x"])
        page = _what_the_page_shows(
            result={"suggested_action": TP},
            gate_result={},
            warnings=["no_table:x"],
            matches=matches,
        )
        assert job.best_pct == page == page_best_pct(matches)
        assert job.basis == "match"

    def test_the_prompts_percentages_are_not_what_the_job_reads(self, world):
        """The prompt's entries are the matches that passed the integrity re-check and the section's own
        checks, and the page shows the best of the STORED matches. When they differ the page's number is the
        rule's: here the entry in the prompt says 62 and the stored matches' best is 91."""
        world.material = _material(62)
        world.matches = [_match(0.62, "e-1"), _match(0.91, "e-2")]

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert rule["best_pct"] == 91 and rule["entry_side"] == "incident"
        assert rule["rule_verdict"] == TP
        assert world.proposer["result"]["suggested_action"] == TP


def _top(
    monkeypatch,
    matches,
    *,
    ranked=None,
    warnings=(),
    conclusions=None,
    threshold=80,
    floor=0.5,
    lookup_id=LOOKUP_ID,
):
    """`triage._rag_top_item` over a lookup row made of `matches` and `ranked` and entries whose conclusions are
    `conclusions` (an id not listed is an incident, `None` is a row that is gone). The two reads are stubbed.
    """
    table = {} if conclusions is None else conclusions

    def conclusions_of(_conn, entry_ids):
        found = {}
        for entry_id in entry_ids:
            conclusion = table.get(entry_id, "confirmed_incident")
            if conclusion is not None:
                found[entry_id] = conclusion
        return found

    monkeypatch.setattr(triage_module, "_lookup_scored", lambda _conn, _id: (matches, ranked))
    monkeypatch.setattr(triage_module, "_entry_conclusions", conclusions_of)
    return triage_module._rag_top_item(None, lookup_id, list(warnings), threshold, floor)


class _StaticConn:
    """A connection that answers the one `SELECT matches, ranked` `_lookup_scored` makes."""

    def __init__(self, matches, ranked=None):
        self._row = (matches, ranked)

    def transaction(self):
        return _NullTransaction()

    def execute(self, _statement, _params=None):
        return SimpleNamespace(fetchone=lambda: self._row)


class _NullTransaction:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------------------------------
# DEC-220 / DEC-225: a lookup that kept no match - the best candidate the rerank scored, under the floor, is the
# top item, and its percentage is the page's `below_floor_pct`
# ---------------------------------------------------------------------------------------------------


def _the_page_pair(proposer, *, matches, ranked, floor=0.5) -> dict:
    """The pair the alert view carries for a stored run: the page's reader over a row shaped as the statement
    returns it (sixteen columns, `queue._Row`: DEC-220's `ranked` after the matches, DEC-221's history and the run's
    token, latency and cost columns after it)."""
    row = (
        "run-1",
        proposer["result"],
        proposer["gate_result"],
        datetime(2026, 11, 15, tzinfo=UTC),
        proposer["citation_warnings"],
        matches,
        ranked,
        None,  # history
        None,  # input_tokens
        None,  # output_tokens
        None,  # latency_ms
        None,  # cost_usd
        None,  # the verifier row's four sums: input_tokens, output_tokens, latency_ms, cost_usd
        None,
        None,
        None,
    )
    return queue.latest_suggestion_rag(_PageConn(row), _ALERT_ID, rag_min_score=floor)[3]


_RANKED = [
    {"entry_id": "c-1", "score": 0.47},
    {"entry_id": "c-2", "score": 0.31},
    {"entry_id": "c-3", "score": 0.12},
]


def _no_match_lookup(world, ranked=_RANKED, **conclusions):
    """The lookup kept no match (the history is in the prompt, so the run names it) and scored `ranked`."""
    world.material = _material(entries=False)
    world.matches = []
    world.ranked = ranked
    world.conclusions = conclusions


class TestACandidateUnderTheFloor:
    """The page says "trùng cao nhất 47% (dưới mức tối thiểu 50%)" for a run whose lookup kept no match and
    scored a 47 % candidate. Since DEC-225 that candidate is the top item of the rule, and 47 is the number it
    compares (`basis` is `below_floor`): the same number the page prints."""

    @pytest.mark.parametrize("threshold", ["80", "100", "51"])
    def test_an_incident_candidate_makes_a_model_true_positive_false_positive(
        self, world, threshold
    ):
        _no_match_lookup(world, **{"c-1": "confirmed_incident"})

        world.run(_tp_model(), TRIAGE_RAG_FP_BELOW_PCT=threshold)

        row = world.proposer
        assert (
            row["rag_lookup_id"] == LOOKUP_ID
        )  # the run names the lookup the page reads the ranking of
        assert row["result"]["suggested_action"] == FP
        assert row["gate_result"]["final_verdict"] == FP
        assert row["gate_result"]["proposed_verdict"] == TP
        assert row["gate_result"]["rag_rule"] == {
            "threshold": int(threshold),
            "best_pct": 47,
            "applied": True,
            "changed": True,
            "entry_side": "incident",
            "rule_verdict": FP,
            "basis": "below_floor",
        }
        assert row["gate_result"]["steps"]["3r"] == "changed"
        assert row["gate_result"]["forced"] is False and row["gate_result"]["forced_by"] == []
        assert "llm.gate_forced" not in world.event_types
        assert world.conclusion_reads == [["c-1"]]  # the top candidate, one entry
        # ... and the number is the page's: its pair for the same stored run says 47 under the 50 floor
        pair = _the_page_pair(row, matches=world.matches, ranked=_RANKED)
        assert pair == {
            "best_pct": None,
            "not_applied": None,
            "below_floor_pct": 47,
            "floor_pct": 50,
        }

    def test_a_benign_candidate_is_not_applied_and_the_models_verdict_stands(self, world):
        _no_match_lookup(world, **{"c-1": "closed_fp"})

        world.run(_tp_model())

        row = world.proposer
        assert row["result"]["suggested_action"] == TP
        assert row["gate_result"]["rag_rule"] == {
            "threshold": 80,
            "best_pct": 47,
            "applied": False,
            "changed": False,
            "entry_side": "benign",
            "rule_verdict": None,
            "basis": "below_floor",
        }
        assert row["gate_result"]["steps"]["3r"] == "n/a"
        assert row["gate_result"]["forced"] is False and row["gate_result"]["forced_by"] == []

    def test_an_incident_candidate_with_a_model_false_positive_is_applied_unchanged(self, world):
        _no_match_lookup(world, **{"c-1": "confirmed_incident"})
        model = _Model(
            [TRIAGE_V4_FALSE_POSITIVE, {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}]
        )

        world.run(model)

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["applied"], rule["changed"], rule["rule_verdict"]) == (True, False, FP)
        assert world.proposer["result"]["suggested_action"] == FP

    def test_the_percentage_is_the_pages_cut_down_number(self, world):
        _no_match_lookup(world, ranked=[{"entry_id": "c-1", "score": 0.4999}])

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert rule["best_pct"] == 49  # cut down, never rounded up to the floor (DEC-221)
        pair = _the_page_pair(
            world.proposer, matches=world.matches, ranked=[{"entry_id": "c-1", "score": 0.4999}]
        )
        assert pair["below_floor_pct"] == 49

    def test_two_candidates_tied_on_the_top_score_with_opposite_sides_the_incident_wins(
        self, world
    ):
        _no_match_lookup(
            world,
            ranked=[{"entry_id": "c-1", "score": 0.4}, {"entry_id": "c-2", "score": 0.4}],
            **{"c-1": "closed_benign", "c-2": "confirmed_incident"},
        )

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"], rule["basis"]) == (
            40,
            "incident",
            "below_floor",
        )
        assert world.proposer["result"]["suggested_action"] == FP  # incident under the threshold

    def test_the_best_candidate_decides_not_the_first_stored(self, world):
        _no_match_lookup(
            world,
            ranked=[{"entry_id": "c-1", "score": 0.2}, {"entry_id": "c-2", "score": 0.45}],
            **{"c-1": "closed_fp", "c-2": "confirmed_incident"},
        )

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"]) == (45, "incident")

    def test_a_candidate_whose_entry_is_gone_gives_no_side(self, world):
        _no_match_lookup(world, **{"c-1": None})

        world.run(_tp_model())

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"], rule["applied"]) == (47, None, False)
        assert world.proposer["result"]["suggested_action"] == TP

    def test_a_lookup_that_scored_nothing_has_no_number_and_reads_no_entry(self, world):
        _no_match_lookup(world, ranked=[])

        world.run(_tp_model())

        assert world.proposer["gate_result"]["rag_rule"]["best_pct"] is None
        assert world.proposer["result"]["suggested_action"] == TP
        assert world.conclusion_reads == []

    def test_a_best_candidate_the_floor_would_now_keep_is_not_below_the_floor(self, world):
        """The page's own rule: the configuration's floor may have moved since the lookup ran, and a candidate it
        would now keep is not "below the floor" - the page shows no number and neither does the rule.
        """
        _no_match_lookup(world, ranked=[{"entry_id": "c-1", "score": 0.55}])

        world.run(_tp_model())  # RAG_MIN_SCORE is 0.5: 0.55 is not under it

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["entry_side"], rule["basis"], rule["applied"]) == (
            None,
            None,
            None,
            False,
        )
        assert world.proposer["result"]["suggested_action"] == TP
        assert world.conclusion_reads == []

    def test_the_floor_is_the_running_configurations(self, world):
        _no_match_lookup(world, ranked=[{"entry_id": "c-1", "score": 0.55}])

        world.run(_tp_model(), RAG_MIN_SCORE="0.6")  # now 0.55 is under the floor

        rule = world.proposer["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["basis"], rule["entry_side"]) == (
            55,
            "below_floor",
            "incident",
        )

    def test_a_kept_match_is_the_top_item_and_the_page_has_no_below_floor_number(self, world):
        """The two are never both set: with a kept match the basis is `match`, whatever else the rerank scored."""
        world.matches = [_match(0.62)]
        world.ranked = [{"entry_id": "e-1", "score": 0.62}, *_RANKED]

        world.run(_tp_model())

        row = world.proposer
        rule = row["gate_result"]["rag_rule"]
        assert (rule["best_pct"], rule["basis"], rule["entry_side"]) == (62, "match", "incident")
        assert row["result"]["suggested_action"] == FP
        pair = _the_page_pair(row, matches=world.matches, ranked=world.ranked)
        assert pair == {
            "best_pct": 62,
            "not_applied": None,
            "below_floor_pct": None,
            "floor_pct": None,
        }

    def test_the_switch_off_reads_neither_the_lookup_nor_the_entry(self, world):
        _no_match_lookup(world, **{"c-1": "confirmed_incident"})

        world.run(_tp_model(), TRIAGE_RAG_FP_BELOW_PCT="0")

        assert world.proposer["result"]["suggested_action"] == TP
        assert world.match_reads == [] and world.conclusion_reads == []
        pair = _the_page_pair(world.proposer, matches=world.matches, ranked=_RANKED)
        assert pair["below_floor_pct"] == 47  # the display does not depend on the switch


class TestTheHelper:
    def test_a_threshold_of_zero_never_touches_the_connection(self):
        got = triage_module._rag_top_item(_Conn(), LOOKUP_ID, [], 0, 0.5)
        assert got == triage_module.RagTop(None, None, None)

    def test_no_lookup_in_the_prompt_never_touches_the_connection(self):
        got = triage_module._rag_top_item(_Conn(), None, [], 80, 0.5)
        assert got == triage_module.RagTop(None, None, None)

    def test_it_reads_the_matches_and_the_ranking_of_the_lookup_the_prompt_held_by_its_id(self):
        seen = []

        class Conn(_StaticConn):
            def execute(self, statement, params=None):
                seen.append((" ".join(str(statement).split()), params))
                return super().execute(statement, params)

        matches = [
            _match(0.62, "not-a-uuid")
        ]  # no entry read: the id is no uuid (`entry_cards` skips it)
        got = triage_module._rag_top_item(Conn(matches), LOOKUP_ID, [], 80, 0.5)

        assert got == triage_module.RagTop(62, None, "match")  # no readable entry, so no side
        assert seen == [
            ("SELECT matches, ranked FROM rag_results WHERE lookup_id = %s", (LOOKUP_ID,))
        ]

    def test_it_reads_the_top_entrys_conclusion_by_id_whatever_its_status(self):
        seen = []

        class Conn(_StaticConn):
            def execute(self, statement, params=None):
                text = " ".join(str(statement).split())
                seen.append((text, params))
                if text.startswith("SELECT entry_id, conclusion"):
                    return SimpleNamespace(fetchall=lambda: [(ENTRY_UUID, "closed_benign", "# t")])
                return super().execute(statement, params)

        matches = [_match(0.9, str(ENTRY_UUID)), _match(0.5, str(uuid.uuid4()))]
        got = triage_module._rag_top_item(Conn(matches), LOOKUP_ID, [], 80, 0.5)

        assert got == triage_module.RagTop(90, "benign", "match")
        statement, params = seen[1]
        assert (
            statement
            == "SELECT entry_id, conclusion, content FROM knowledge_entries WHERE entry_id = ANY(%s)"
        )
        assert "status" not in statement  # the entry is read whatever its status
        assert params == ([ENTRY_UUID],)  # one entry: the top one

    def test_a_missing_row_gives_no_number(self):
        class Conn(_StaticConn):
            def execute(self, statement, params=None):
                return SimpleNamespace(fetchone=lambda: None)

        got = triage_module._rag_top_item(Conn(None), LOOKUP_ID, [], 80, 0.5)
        assert got == triage_module.RagTop(None, None, None)

    def test_a_database_error_on_the_lookup_is_no_number_never_a_failed_run(self):
        import psycopg

        class Conn(_StaticConn):
            def transaction(self):
                raise psycopg.OperationalError("boom")

        got = triage_module._rag_top_item(Conn(None), LOOKUP_ID, [], 80, 0.5)
        assert got == triage_module.RagTop(None, None, None)

    def test_a_database_error_on_the_entry_is_a_number_with_no_side_never_a_failed_run(self):
        import psycopg

        class Conn(_StaticConn):
            def execute(self, statement, params=None):
                if " ".join(str(statement).split()).startswith("SELECT entry_id, conclusion"):
                    raise psycopg.OperationalError("boom")
                return super().execute(statement, params)

        matches = [_match(0.9, str(ENTRY_UUID))]
        got = triage_module._rag_top_item(Conn(matches), LOOKUP_ID, [], 80, 0.5)
        assert got == triage_module.RagTop(90, None, "match")

    @pytest.mark.parametrize("floor", [None, "0.5", True, float("nan"), 1.5])
    def test_a_floor_that_is_not_a_score_gives_no_below_floor_number(self, monkeypatch, floor):
        got = _top(monkeypatch, [], ranked=[{"entry_id": "c", "score": 0.3}], floor=floor)
        assert got == triage_module.RagTop(None, None, None)

    def test_a_failed_lookup_gives_no_number_even_with_stored_matches(self, monkeypatch):
        got = _top(monkeypatch, [_match(0.9)], warnings=["rag_not_applied:auth"])
        assert got == triage_module.RagTop(None, None, None)

    @pytest.mark.parametrize(
        "conclusion, side",
        [
            ("confirmed_incident", "incident"),
            ("closed_fp", "benign"),
            ("closed_benign", "benign"),
            ("concluded_fp", "benign"),
            ("concluded_policy_violation", "benign"),
            ("need_more_data", None),
            ("", None),
            (None, None),
            (7, None),
            (["confirmed_incident"], None),
        ],
    )
    def test_the_side_of_a_conclusion(self, conclusion, side):
        assert triage_module.entry_side(conclusion) == side

    def test_every_conclusion_the_schema_allows_has_a_side(self):
        """The CHECK of `knowledge_entries.conclusion` (migration 020) is the list; a conclusion added there with no
        side here would silently give no rule."""
        schema = (
            Path(__file__).resolve().parents[2] / "docs" / "Schema" / "020_learned_knowledge.sql"
        ).read_text(encoding="utf-8")
        block = schema[schema.index("ck_knowledge_entries_conclusion") :]
        allowed = re.findall(r"'([a-z_]+)'", block[: block.index("))")])
        assert set(allowed) == {
            "closed_fp",
            "closed_benign",
            "concluded_fp",
            "concluded_policy_violation",
            "confirmed_incident",
        }
        assert {triage_module.entry_side(name) for name in allowed} == {"incident", "benign"}
        assert [n for n in allowed if triage_module.entry_side(n) is None] == []


# ---------------------------------------------------------------------------------------------------
# the evaluation: both gate modes, TriageEvaluation (spec 4)
# ---------------------------------------------------------------------------------------------------


class TestTheEvaluation:
    def _evaluate(self, world, switches, model):
        return evaluate_alert(None, _ALERT_ID, adapter=model, cfg=config.load(), switches=switches)

    def test_the_deployed_gate_ends_with_the_rules_verdict_and_forces_nothing(self, world):
        ev = self._evaluate(world, EvalSwitches(rag=True), _tp_model())

        assert ev.outcome == "ok"
        assert (ev.proposed_verdict, ev.final_verdict) == (
            TP,
            FP,
        )  # they differ when the rule changed it
        assert ev.forced_by == ()  # and it is not a gate force
        assert "rag_rule" not in ev.flagged_by
        assert ev.gate_result["rag_rule"]["changed"] is True
        assert ev.verdict_for_verifier == TP  # the verifier row's `compared_to`
        assert ev.result["suggested_action"] == FP
        assert ev.reasons_kept == 1 and ev.reasons_dropped == 0

    def test_a_run_the_rule_did_not_change_has_the_same_verdict_twice(self, world):
        world.matches = [_match(0.9)]

        ev = self._evaluate(world, EvalSwitches(rag=True), _tp_model())

        assert ev.forced_by == () and ev.final_verdict == ev.proposed_verdict == TP

    def test_the_restricted_mode_runs_the_rule_too(self, world):
        model = _Model([TRIAGE_V4_TRUE_POSITIVE])

        ev = self._evaluate(world, EvalSwitches(rag=True, gate_mode="steps_1_3"), model)

        assert ev.outcome == "ok"
        assert len(model.requests) == 1  # steps 1-3 only: no verifier call
        assert (ev.proposed_verdict, ev.final_verdict) == (TP, FP)
        assert ev.forced_by == ()
        assert ev.gate_result["steps"]["3r"] == "changed"
        assert "4" not in ev.gate_result["steps"] and "6" not in ev.gate_result["steps"]
        assert ev.gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": 62,
            "applied": True,
            "changed": True,
            "entry_side": "incident",
            "rule_verdict": FP,
            "basis": "match",
        }
        assert ev.result["suggested_action"] == FP

    def test_an_incident_at_the_threshold_turns_a_model_false_positive_into_true_positive_in_both_modes(
        self, world
    ):
        world.matches = [_match(0.85)]
        answers_fp = {**VERIFIER_V2_AGREE, "structured_only_verdict": FP}

        deployed = self._evaluate(
            world, EvalSwitches(rag=True), _Model([TRIAGE_V4_FALSE_POSITIVE, answers_fp])
        )
        restricted = self._evaluate(
            world,
            EvalSwitches(rag=True, gate_mode="steps_1_3"),
            _Model([TRIAGE_V4_FALSE_POSITIVE]),
        )

        for ev in (deployed, restricted):
            assert ev.outcome == "ok"
            assert (ev.proposed_verdict, ev.final_verdict) == (FP, TP)
            assert ev.forced_by == () and ev.result["suggested_action"] == TP
            assert ev.gate_result["steps"]["3r"] == "changed"
            assert ev.gate_result["rag_rule"]["rule_verdict"] == TP
        assert deployed.verdict_for_verifier == FP  # the verifier is sent the model's own verdict

    def test_the_restricted_mode_with_the_switch_off_is_the_model_and_an_n_a_step(self, world):
        world.setenv("TRIAGE_RAG_FP_BELOW_PCT", "0")

        ev = self._evaluate(
            world, EvalSwitches(rag=True, gate_mode="steps_1_3"), _Model([TRIAGE_V4_TRUE_POSITIVE])
        )

        assert ev.final_verdict == TP and ev.forced_by == ()
        assert ev.gate_result["steps"]["3r"] == "n/a"
        assert world.match_reads == []

    def test_an_evaluation_without_rag_has_no_number_so_no_rule(self, world):
        """The evaluation harness builds its switches without `rag`: no live lookup reaches it, and so no
        rule (`EvalSwitches.rag` is the switch of the lookup, the rule needs a lookup)."""
        ev = self._evaluate(world, EvalSwitches(), _tp_model())

        assert ev.final_verdict == TP and ev.forced_by == ()
        assert ev.gate_result["rag_rule"]["best_pct"] is None
        assert world.material_reads == 0 and world.match_reads == []

    def test_a_run_whose_verifier_call_failed_still_ended_with_the_rules_verdict(self, world):
        from app.llm.adapter import LLMBudgetExceeded

        model = _Model(
            [TRIAGE_V4_TRUE_POSITIVE, VERIFIER_V2_AGREE],
            raises_from=1,
            exc=LLMBudgetExceeded("cap"),
        )

        ev = self._evaluate(world, EvalSwitches(rag=True), model)

        assert ev.outcome == "verifier_cap"
        assert ev.final_verdict is None and ev.gate_result is None  # as before: only "ok" has them
        assert ev.forced_by == ()
        assert ev.proposed_verdict == TP and ev.state.verdict == FP
        assert ev.verdict_for_verifier == TP  # the verifier was sent the model's own verdict
