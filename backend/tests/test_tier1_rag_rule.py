"""`tier1.triage` and the RAG low-match rule (DEC-219,
`docs/superpowers/specs/2026-11-15-rag-low-match-fp-rule-design.md` sections 2, 4, 5 and 7): what the run
computes (`best_pct`), what the gate is handed, what the verifier is sent, and what is stored. NO DATABASE.

`run_triage_job` and `evaluate_alert` are the real code; what touches the database is replaced by recorders (the
alert read, the correlation read, the idle-timeout statement, `llm_runs.write_run`, `_set_triage_status`,
`write_event`) and by two stubs for the RAG: the lookup's status and material (`lookup_failure`,
`lookup_material`) and the stored `matches` of the lookup the prompt held (`_lookup_matches`). The database-backed
counterpart, which stores real rows and reads them back through the alert page's own statement, is
`test_rag_rule_db.py` (marked `db`; it cannot run on a host whose `TEST_DATABASE_URL` does not
authenticate).

The central claim of the card: `best_pct` is the number the alert page shows for the same stored run. The page
reads the `matches` of the lookup the run's row names and the run's `citation_warnings` through
`llm.rag_view.rag_view` (`tier1.queue.latest_suggestion_rag`); the job reads the same two things through the same
function, so the tests below feed ONE stored run to both and compare.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
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
        material_reads=0,
        match_reads=[],
    )

    def _write_run(_conn, **kwargs):
        writes.runs.append(kwargs)
        return kwargs["run_id"]

    def _lookup_material(_conn, _subject, **_kw):
        writes.material_reads += 1
        return writes.material

    def _lookup_matches(_conn, lookup_id):
        writes.match_reads.append(lookup_id)
        return writes.matches

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
    monkeypatch.setattr(triage_module, "_lookup_matches", _lookup_matches)

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


class TestAMatchBelowTheThreshold:
    def test_a_true_positive_is_stored_as_false_positive_beside_the_models_answer(self, world):
        world.run(_tp_model())

        row = world.proposer
        assert row["result"]["suggested_action"] == FP  # what ① ended with, what Tier 1 is served
        gate_result = row["gate_result"]
        assert gate_result["version"] == 2
        assert gate_result["proposed_verdict"] == TP  # the model's own answer
        assert gate_result["final_verdict"] == FP
        # the rule is ①'s default answer below the threshold, not a gate force: the record is `rag_rule`
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert gate_result["rag_rule"] == {
            "threshold": 80,
            "best_pct": 62,
            "applied": True,
            "changed": True,
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
        }
        assert gate_result["steps"]["3r"] == "applied"
        assert world.event_types == ["triage.suggested"]  # llm.gate_forced is never written
        assert _event(world, "triage.suggested")["forced"] is False


class TestARuleThatDoesNotApply:
    @pytest.mark.parametrize("score, pct", [(0.80, 80), (0.81, 81), (0.95, 95), (1.0, 100)])
    def test_a_best_match_at_or_above_the_threshold_leaves_the_models_verdict(
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
            "applied": False,
            "changed": False,
        }
        assert gate_result["steps"]["3r"] == "n/a"
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert world.event_types == ["triage.suggested"]

    def test_the_best_of_several_matches_decides_not_the_first_or_the_lowest(self, world):
        world.matches = [_match(0.55, "e-1"), _match(0.91, "e-2"), _match(0.62, "e-3")]

        world.run(_tp_model())

        assert world.proposer["gate_result"]["rag_rule"]["best_pct"] == 91
        assert world.proposer["result"]["suggested_action"] == TP

    def test_the_switch_off_leaves_it_whatever_the_match_and_reads_nothing_more(self, world):
        world.run(_tp_model(), TRIAGE_RAG_FP_BELOW_PCT="0")

        gate_result = world.proposer["gate_result"]
        assert world.proposer["result"]["suggested_action"] == TP
        assert gate_result["rag_rule"] == {
            "threshold": 0,
            "best_pct": None,
            "applied": False,
            "changed": False,
        }
        assert gate_result["steps"]["3r"] == "n/a"
        assert world.match_reads == []  # not one statement more than before the key existed
        assert world.event_types == ["triage.suggested"]

    def test_with_the_switch_unset_it_is_the_same_as_zero(self, world, monkeypatch):
        monkeypatch.delenv("TRIAGE_RAG_FP_BELOW_PCT", raising=False)

        world.run(_tp_model())

        assert world.proposer["gate_result"]["rag_rule"]["threshold"] == 0
        assert world.proposer["result"]["suggested_action"] == TP
        assert world.match_reads == []


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
# best_pct is None where the page shows no number (spec 2)
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
        }
        assert gate_result["steps"]["3r"] == "n/a"
        assert gate_result["forced"] is False and gate_result["forced_by"] == []
        assert "llm.gate_forced" not in world.event_types

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
        world.matches = None  # `_lookup_matches` answers None for a missing or an unreadable row

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
        world.match_reads.clear()  # that evaluation read the matches once; this is about the job below

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
    row = ("run-1", result, gate_result, datetime(2026, 11, 15, tzinfo=UTC), warnings, matches)
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
        assert world.proposer["gate_result"]["rag_rule"]["applied"] is (
            gate_best is not None and gate_best < 80
        )

    @pytest.mark.parametrize(
        "warnings", [["learned_entries_dropped"], ["x", "learned_entries_dropped"]]
    )
    @pytest.mark.parametrize("matches", [[_match(0.62)], [_match(0.9)], [], None])
    def test_the_entries_dropped_warning_gives_no_number_to_both(self, matches, warnings):
        lookup = LOOKUP_ID
        job = triage_module._rag_best_pct(_StaticConn(matches), lookup, warnings, 80)
        page = _what_the_page_shows(
            result={"suggested_action": TP},
            gate_result={},
            warnings=warnings,
            matches=matches,
        )
        assert job is None and page is None

    @pytest.mark.parametrize(
        "matches", [[_match(0.62)], [_match(0.9)], [_match(0.5), _match(0.71)]]
    )
    def test_without_the_warning_both_give_the_best_of_the_stored_matches(self, matches):
        job = triage_module._rag_best_pct(_StaticConn(matches), LOOKUP_ID, ["no_table:x"], 80)
        page = _what_the_page_shows(
            result={"suggested_action": TP},
            gate_result={},
            warnings=["no_table:x"],
            matches=matches,
        )
        assert job == page == page_best_pct(matches)

    def test_the_prompts_percentages_are_not_what_the_job_reads(self, world):
        """The prompt's entries are the matches that passed the integrity re-check and the section's own
        checks, and the page shows the best of the STORED matches. When they differ the page's number is the
        rule's: here the entry in the prompt says 62 and the stored matches' best is 91."""
        world.material = _material(62)
        world.matches = [_match(0.62, "e-1"), _match(0.91, "e-2")]

        world.run(_tp_model())

        assert world.proposer["gate_result"]["rag_rule"]["best_pct"] == 91
        assert world.proposer["result"]["suggested_action"] == TP


class _StaticConn:
    """A connection that answers the one `SELECT matches` `_lookup_matches` makes with `matches`."""

    def __init__(self, matches):
        self._matches = matches

    def transaction(self):
        return _NullTransaction()

    def execute(self, _statement, _params=None):
        return SimpleNamespace(fetchone=lambda: (self._matches,))


class _NullTransaction:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------------------------------
# DEC-220: the number the page shows for a lookup that kept no match is NOT the rule's number
# ---------------------------------------------------------------------------------------------------


def _the_page_pair(proposer, *, matches, ranked, floor=0.5) -> dict:
    """The pair the alert view carries for a stored run: the page's reader over a row shaped as the statement
    returns it (DEC-220: the lookup's `ranked` is its last column)."""
    row = (
        "run-1",
        proposer["result"],
        proposer["gate_result"],
        datetime(2026, 11, 15, tzinfo=UTC),
        proposer["citation_warnings"],
        matches,
        ranked,
    )
    return queue.latest_suggestion_rag(_PageConn(row), _ALERT_ID, rag_min_score=floor)[3]


_RANKED = [{"entry_id": "c-1", "score": 0.47}, {"entry_id": "c-2", "score": 0.31}]


class TestACandidateUnderTheFloorIsNotAMatch:
    """The page says "trùng cao nhất 47% (dưới mức tối thiểu 50%)" for a run whose lookup kept no match and
    scored a 47 % candidate. The rule of DEC-219 reads kept matches only (`_rag_best_pct`): for the same stored run
    it has no number, does not apply and leaves the model's verdict, whatever the threshold. The two can never be
    confused: this class pins the one against the other."""

    @pytest.mark.parametrize("threshold", ["80", "100", "51"])
    def test_a_47_percent_candidate_with_no_kept_match_keeps_the_models_verdict(
        self, world, threshold
    ):
        world.material = _material(
            entries=False
        )  # history only: the run holds the lookup; no entry
        world.matches = []  # the lookup kept no match: 47 % is under the floor of 50 %

        world.run(_tp_model(), TRIAGE_RAG_FP_BELOW_PCT=threshold)

        row = world.proposer
        assert (
            row["rag_lookup_id"] == LOOKUP_ID
        )  # the run names the lookup the page reads the ranking of
        assert row["result"]["suggested_action"] == TP
        assert row["gate_result"]["final_verdict"] == TP
        assert row["gate_result"]["rag_rule"] == {
            "threshold": int(threshold),
            "best_pct": None,
            "applied": False,
            "changed": False,
        }
        assert row["gate_result"]["steps"]["3r"] == "n/a"
        assert row["gate_result"]["forced"] is False and row["gate_result"]["forced_by"] == []
        assert "llm.gate_forced" not in world.event_types
        # ... while the page pair for the same stored run has the candidate's percentage
        pair = _the_page_pair(row, matches=world.matches, ranked=_RANKED)
        assert pair == {
            "best_pct": None,
            "not_applied": None,
            "below_floor_pct": 47,
            "floor_pct": 50,
        }

    def test_the_rule_reads_the_stored_matches_and_never_the_ranking(self, world):
        world.material = _material(entries=False)
        world.matches = []

        world.run(_tp_model())

        # `_rag_best_pct` read the one thing it always read: the matches of the lookup the prompt held
        assert world.match_reads == [LOOKUP_ID]
        assert world.proposer["gate_result"]["rag_rule"]["best_pct"] is None

    def test_a_kept_match_is_the_rules_number_and_the_page_has_no_below_floor_number(self, world):
        world.matches = [_match(0.62)]

        world.run(_tp_model())

        row = world.proposer
        assert row["gate_result"]["rag_rule"]["best_pct"] == 62
        assert row["result"]["suggested_action"] == FP
        pair = _the_page_pair(
            row, matches=world.matches, ranked=[{"entry_id": "e-1", "score": 0.62}, *_RANKED]
        )
        assert pair == {
            "best_pct": 62,
            "not_applied": None,
            "below_floor_pct": None,
            "floor_pct": None,
        }

    def test_a_row_of_the_statement_before_dec_220_has_no_ranking(self, world):
        """Six columns, no `ranked`: the reader takes it as a lookup with none, and says nothing of a floor."""
        world.matches = []
        world.run(_tp_model())
        proposer = world.proposer
        row = (
            "run-1",
            proposer["result"],
            proposer["gate_result"],
            datetime(2026, 11, 15, tzinfo=UTC),
            proposer["citation_warnings"],
            world.matches,
        )

        pair = queue.latest_suggestion_rag(_PageConn(row), _ALERT_ID, rag_min_score=0.5)[3]

        assert pair == {
            "best_pct": None,
            "not_applied": None,
            "below_floor_pct": None,
            "floor_pct": None,
        }


class TestTheHelper:
    def test_a_threshold_of_zero_never_touches_the_connection(self):
        assert triage_module._rag_best_pct(_Conn(), LOOKUP_ID, [], 0) is None

    def test_no_lookup_in_the_prompt_never_touches_the_connection(self):
        assert triage_module._rag_best_pct(_Conn(), None, [], 80) is None

    def test_it_reads_the_matches_of_the_lookup_the_prompt_held_by_its_id(self):
        seen = []

        class Conn(_StaticConn):
            def execute(self, statement, params=None):
                seen.append((" ".join(str(statement).split()), params))
                return super().execute(statement, params)

        got = triage_module._rag_best_pct(Conn([_match(0.62)]), LOOKUP_ID, [], 80)

        assert got == 62
        assert seen == [("SELECT matches FROM rag_results WHERE lookup_id = %s", (LOOKUP_ID,))]

    def test_a_missing_row_gives_no_number(self):
        class Conn(_StaticConn):
            def execute(self, statement, params=None):
                return SimpleNamespace(fetchone=lambda: None)

        assert triage_module._rag_best_pct(Conn(None), LOOKUP_ID, [], 80) is None

    def test_a_database_error_is_no_number_never_a_failed_run(self):
        import psycopg

        class Conn(_StaticConn):
            def transaction(self):
                raise psycopg.OperationalError("boom")

        assert triage_module._rag_best_pct(Conn(None), LOOKUP_ID, [], 80) is None


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
        }
        assert ev.result["suggested_action"] == FP

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
