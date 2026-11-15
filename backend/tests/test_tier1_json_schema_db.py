"""`run_triage_job` on a database and DEC-218 (spec sections 5, 6 and 8): the columns, read back from Postgres.

The same rules `test_tier1_json_schema.py` pins with recorders for the database, here against the real rows:

* `gate_result.step1_errors` of a run the repair round fixed, `[]` for one valid at once;
* the `stopped_by = 'schema'` row's `gate_result` keeps `schema_errors` and gains `first_errors`;
* `response_format_fallback` in the proposer row's `citation_warnings` when a call of the run asked for
  `json_schema` and was answered as `json_object`;
* none of the stored messages is in any prompt the rows record.

MARKED `db`: it needs `TEST_DATABASE_URL`. WRITTEN FOR DEC-218 (JS-T1) ON A HOST WHERE THAT URL DOES NOT
AUTHENTICATE, SO NOT RUN THERE (`make test-db TESTS=backend/tests/test_tier1_json_schema_db.py` where it can).
"""

from __future__ import annotations

import copy

import pytest
from app.llm.adapter import LLMBudgetExceeded, LLMResult
from app.llm.triage import RESPONSE_FORMAT_FALLBACK
from app.tier1.triage import run_triage_job

from tests.fakes.llm import TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE
from tests.test_triage_job import _enable_llm, _job, _RecordingLLM, _seed_alert

pytestmark = pytest.mark.db

MISSPELT = copy.deepcopy(TRIAGE_V3_TRUE_POSITIVE)
MISSPELT["reasones"] = MISSPELT.pop("reasons")
WRONG_ENUM = {**TRIAGE_V3_TRUE_POSITIVE, "suggested_action": "maybe"}


class _FormatAwareLLM(_RecordingLLM):
    """`_RecordingLLM` whose results say which format produced them, as the real adapter's do; the calls whose
    index is in `fall_back` are answered as `json_object` although they asked for `json_schema`. With
    `fail_from`, every call from that index on raises the cap error (the verifier's, when it is 1).
    """

    def __init__(self, *args, fall_back=(), fail_from=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._fall_back = set(fall_back)
        self._fail_from = fail_from

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        index = len(self.calls)
        if self._fail_from is not None and index >= self._fail_from:
            raise LLMBudgetExceeded("over the monthly cap")
        got = super().complete(
            system=system,
            user=user,
            response_format=response_format,
            timeout_s=timeout_s,
            model=model,
        )
        asked = (response_format or {"type": "json_object"})["type"]
        return LLMResult(
            content=got.content,
            model=got.model,
            usage=got.usage,
            latency_ms=got.latency_ms,
            response_format="json_object" if index in self._fall_back else asked,
        )


def _proposer(db, alert_id: str) -> tuple:
    return db.execute(
        "SELECT gate_result, citation_warnings, stopped_by, system_prompt, user_message "
        "FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()


def _verifier(db, alert_id: str) -> tuple:
    return db.execute(
        "SELECT gate_result, citation_warnings, system_prompt, user_message "
        "FROM llm_runs WHERE subject_id = %s AND role = 'verifier'",
        (alert_id,),
    ).fetchone()


def test_a_repaired_run_stores_step1_errors_and_a_run_valid_at_once_stores_none(db, monkeypatch):
    _enable_llm(monkeypatch)
    repaired_id, plain_id = _seed_alert(db), _seed_alert(db)

    run_triage_job(
        db,
        _job(repaired_id),
        adapter=_FormatAwareLLM(responses=[MISSPELT, TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE]),
    )
    run_triage_job(
        db,
        _job(plain_id),
        adapter=_FormatAwareLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE]),
    )

    repaired_gate = _proposer(db, repaired_id)[0]
    assert repaired_gate["version"] == 2 and repaired_gate["steps"]["1"] == "repaired"
    assert "reasones: unexpected key" in repaired_gate["step1_errors"]
    plain_gate = _proposer(db, plain_id)[0]
    assert plain_gate["steps"]["1"] == "ok" and plain_gate["step1_errors"] == []


def test_the_schema_stopped_row_keeps_schema_errors_and_gains_first_errors(db, monkeypatch):
    _enable_llm(monkeypatch)
    alert_id = _seed_alert(db)
    fake = _FormatAwareLLM(responses=[MISSPELT, WRONG_ENUM])

    run_triage_job(db, _job(alert_id), adapter=fake)

    gate_result, _warnings, stopped_by, _system, _user = _proposer(db, alert_id)
    assert stopped_by == "schema"
    assert set(gate_result) == {"error", "schema_errors", "first_errors", "facts"}
    assert "reasones: unexpected key" in gate_result["first_errors"]
    assert gate_result["schema_errors"] == [
        "suggested_action: expected one of false_positive|true_positive"
    ]
    assert len(fake.calls) == 2  # the one repair round, never a third call


@pytest.mark.parametrize("fall_back", [{0}, {1}, {0, 1, 2}], ids=["first", "verifier", "all"])
def test_a_fallback_puts_the_warning_in_the_proposer_rows_citation_warnings(
    db, monkeypatch, fall_back
):
    _enable_llm(monkeypatch)
    monkeypatch.setenv("LLM_RESPONSE_FORMAT", "json_schema")
    alert_id = _seed_alert(db)
    fake = _FormatAwareLLM(
        responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE], fall_back=fall_back
    )

    run_triage_job(db, _job(alert_id), adapter=fake)

    warnings = _proposer(db, alert_id)[1]
    assert warnings.count(RESPONSE_FORMAT_FALLBACK) == 1
    assert RESPONSE_FORMAT_FALLBACK not in (_verifier(db, alert_id)[1] or [])
    assert [c["response_format"]["json_schema"]["name"] for c in fake.calls] == [
        "triage_v3",
        "verifier_v2",
    ]


def test_without_a_fallback_or_with_the_switch_off_there_is_no_warning(db, monkeypatch):
    _enable_llm(monkeypatch)
    on_id, off_id = _seed_alert(db), _seed_alert(db)

    monkeypatch.setenv("LLM_RESPONSE_FORMAT", "json_schema")
    run_triage_job(
        db,
        _job(on_id),
        adapter=_FormatAwareLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE]),
    )
    monkeypatch.delenv("LLM_RESPONSE_FORMAT")
    off = _FormatAwareLLM(responses=[TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE], fall_back={0, 1})
    run_triage_job(db, _job(off_id), adapter=off)

    assert RESPONSE_FORMAT_FALLBACK not in (_proposer(db, on_id)[1] or [])
    assert RESPONSE_FORMAT_FALLBACK not in (_proposer(db, off_id)[1] or [])
    assert all(c["response_format"] is None for c in off.calls)  # nothing was passed


def test_the_warning_survives_a_verifier_that_then_fails(db, monkeypatch):
    _enable_llm(monkeypatch)
    monkeypatch.setenv("LLM_RESPONSE_FORMAT", "json_schema")
    alert_id = _seed_alert(db)
    fake = _FormatAwareLLM(responses=[TRIAGE_V3_TRUE_POSITIVE], fall_back={0}, fail_from=1)

    run_triage_job(db, _job(alert_id), adapter=fake)

    _gate, warnings, stopped_by, _system, _user = _proposer(db, alert_id)
    assert stopped_by == "cap"
    assert warnings.count(RESPONSE_FORMAT_FALLBACK) == 1


def test_no_stored_message_is_in_a_prompt_the_rows_record(db, monkeypatch):
    _enable_llm(monkeypatch)
    monkeypatch.setenv("LLM_RESPONSE_FORMAT", "json_schema")
    alert_id = _seed_alert(db)
    fake = _FormatAwareLLM(responses=[MISSPELT, TRIAGE_V3_TRUE_POSITIVE, VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    gate_result, _warnings, _stopped_by, system_prompt, user_message = _proposer(db, alert_id)
    assert "reasones" in " ".join(gate_result["step1_errors"])  # stored ...
    verifier_gate, _vwarnings, verifier_system, verifier_user = _verifier(db, alert_id)
    for text in (system_prompt, user_message, verifier_system, verifier_user):
        assert "reasones" not in text  # ... and in no prompt
    assert "reasones" not in str(verifier_gate)
    for call in fake.calls:
        assert "reasones" not in call["system"] + call["user"]
