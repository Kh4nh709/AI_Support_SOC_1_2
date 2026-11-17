"""DEC-223, Task 2 - the MITRE reference through `tier1.triage` on a database, with the fake adapter.

`test_triage_prompt_mitre.py` pins the section the builder writes. This file pins what only the orchestration can
show, on the real `run_triage_job` and `evaluate_alert` (the stored `llm_runs` rows):

* the switch is read from the environment by the job, and a run whose prompt carried the section says so in its
  stored `citation_warnings` (`mitre_reference:<version>`), a run without it does not;
* ① records no injection finding for the reference block (the call site uses `_injection_findings`, not the
  detector over every block), while the same words in the alert's own description are still found and stored;
* a missing extract is not an error of the alert: it is still triaged, without the section, with the warning;
* a model that cites `mitre_reference` as a reason's source ends the run as `schema` (no result is kept).

Needs a database (`TEST_DATABASE_URL`); no model, no socket.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

import pytest
from app.kb import mitre
from app.llm import builder as B
from app.security import detector, wrap
from app.tier1.triage import DEPLOYED, evaluate_alert, run_triage_job

from tests.fakes.llm import TRIAGE_V4_TRUE_POSITIVE, VERIFIER_V2_AGREE
from tests.test_llm_triage import NONCE
from tests.test_triage_job import _enable_llm, _job, _RecordingLLM, _seed_alert
from tests.test_triage_prompt_mitre import HOSTILE, IDS, write_extract
from tests.test_triage_rag import cfg  # noqa: F401 - the fixture, by name

ENV = "PROMPT_INCLUDE_MITRE_REFERENCE"


@pytest.fixture(autouse=True)
def _fresh_reference():
    mitre.reset_cache()
    yield
    mitre.reset_cache()


@pytest.fixture
def fixed_nonce(monkeypatch) -> None:
    monkeypatch.setattr(wrap, "new_nonce", lambda: NONCE)


def llm(*answers) -> _RecordingLLM:
    return _RecordingLLM(responses=list(answers) or [TRIAGE_V4_TRUE_POSITIVE, VERIFIER_V2_AGREE])


def proposer_row(db, alert_id: str) -> dict:
    columns = ("user_message", "citation_warnings", "injection_findings", "result", "stopped_by")
    row = db.execute(
        f"SELECT {', '.join(columns)} FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    return dict(zip(columns, row, strict=True))


def triage_status(db, alert_id: str) -> str:
    return db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()[0]


# ───────────────────────────────────────────────────────── the stored run
@pytest.mark.db
def test_a_run_with_the_switch_on_stores_the_section_and_the_version_mark(db, monkeypatch) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setenv(ENV, "true")
    alert_id = _seed_alert(db, mitre_ids=list(IDS))

    run_triage_job(db, _job(alert_id), adapter=llm())

    row = proposer_row(db, alert_id)
    assert B.HEADING_MITRE_REFERENCE in row["user_message"]
    assert 'source="mitre_reference"' in row["user_message"]
    assert "T1110.001 Password Guessing" in row["user_message"]
    assert row["citation_warnings"] == [f"mitre_reference:{mitre.version()}"]
    assert row["stopped_by"] is None and triage_status(db, alert_id) != "unavailable"


@pytest.mark.db
def test_a_run_with_the_switch_off_is_what_it_was(db, monkeypatch) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.delenv(ENV, raising=False)
    alert_id = _seed_alert(db, mitre_ids=list(IDS))

    run_triage_job(db, _job(alert_id), adapter=llm())

    row = proposer_row(db, alert_id)
    assert B.HEADING_MITRE_REFERENCE not in row["user_message"]
    assert "mitre_reference" not in row["user_message"]
    assert row["citation_warnings"] == []


@pytest.mark.db
def test_the_section_is_the_only_difference_between_on_and_off(
    db, cfg, fixed_nonce  # noqa: F811
) -> None:
    alert_id = _seed_alert(db, mitre_ids=list(IDS))
    on = evaluate_alert(
        db,
        alert_id,
        adapter=llm(),
        cfg=dataclasses.replace(cfg, PROMPT_INCLUDE_MITRE_REFERENCE=True),
        switches=DEPLOYED,
    )
    off = evaluate_alert(
        db,
        alert_id,
        adapter=llm(),
        cfg=dataclasses.replace(cfg, PROMPT_INCLUDE_MITRE_REFERENCE=False),
        switches=DEPLOYED,
    )
    assert on is not None and off is not None and on.outcome == off.outcome == "ok"
    user = on.built.prompt.user
    start, end = user.index(B.HEADING_MITRE_REFERENCE), user.index(B.HEADING_REQUEST)
    assert user[:start] + user[end:] == off.built.prompt.user
    assert on.facts == off.facts  # no fact, no verdict input changes
    assert on.final_verdict == off.final_verdict


# ───────────────────────────────────────────────────────── the injection detector
@pytest.mark.db
def test_the_job_records_no_finding_for_the_reference_but_does_for_the_alert(
    db, monkeypatch, tmp_path
) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setenv(ENV, "true")
    hostile = write_extract(
        tmp_path, {"T1110": ("Brute Force", ["credential-access"], None, HOSTILE)}
    )
    monkeypatch.setattr(mitre, "MITRE_FILE", hostile)
    mitre.reset_cache()

    clean = _seed_alert(db, mitre_ids=["T1110"])
    run_triage_job(db, _job(clean), adapter=llm())
    row = proposer_row(db, clean)
    assert "Brute Force" in row["user_message"]  # the hostile block was in the prompt...
    assert row["injection_findings"] == []  # ...and ① recorded nothing for it

    # the control: the detector does find these words, and ① still stores a finding for the alert's own text
    attack = _seed_alert(db, mitre_ids=["T1110"], description=HOSTILE)
    run_triage_job(db, _job(attack), adapter=llm())
    found = proposer_row(db, attack)["injection_findings"]
    assert found and {f["source"] for f in found} == {"rule_description"}
    assert detector.scan([wrap.untrusted_block(HOSTILE, "mitre_reference", nonce=NONCE)])


# ───────────────────────────────────────────────────────── a missing extract
@pytest.mark.db
def test_a_missing_extract_is_not_an_error_of_the_alert(db, monkeypatch, tmp_path) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setenv(ENV, "true")
    monkeypatch.setattr(mitre, "MITRE_FILE", tmp_path / "absent.json")
    mitre.reset_cache()
    alert_id = _seed_alert(db, mitre_ids=list(IDS))

    run_triage_job(db, _job(alert_id), adapter=llm())

    row = proposer_row(db, alert_id)
    assert row["stopped_by"] is None and row["result"] is not None  # triaged, a verdict was stored
    assert "mitre_reference" not in row["user_message"]
    assert row["citation_warnings"] == ["mitre_reference_unavailable"]
    assert triage_status(db, alert_id) != "unavailable"


@pytest.mark.db
def test_a_damaged_extract_is_not_an_error_of_the_alert_either(db, monkeypatch, tmp_path) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setenv(ENV, "true")
    broken: Path = tmp_path / "extract.json"
    broken.write_text(
        '{"header": {"domain": "enterprise-attack", "version": "20.1"}, "techniques": [', "utf-8"
    )
    monkeypatch.setattr(mitre, "MITRE_FILE", broken)
    mitre.reset_cache()
    alert_id = _seed_alert(db, mitre_ids=list(IDS))

    run_triage_job(db, _job(alert_id), adapter=llm())

    row = proposer_row(db, alert_id)
    assert row["result"] is not None and row["citation_warnings"] == ["mitre_reference_unavailable"]


# ───────────────────────────────────────────────────────── A3: the reference is not a source
@pytest.mark.db
def test_a_reason_that_cites_the_reference_ends_the_run_as_schema_and_keeps_nothing(
    db, monkeypatch
) -> None:
    _enable_llm(monkeypatch)
    monkeypatch.setenv(ENV, "true")
    alert_id = _seed_alert(db, mitre_ids=list(IDS))
    bad = copy.deepcopy(TRIAGE_V4_TRUE_POSITIVE)
    bad["reasons"] = [
        {"claim": "kỹ thuật dò mật khẩu", "quote": "Password Guessing", "source": "mitre_reference"}
    ]
    fake = _RecordingLLM(responses=[json.dumps(bad), json.dumps(bad), VERIFIER_V2_AGREE])

    run_triage_job(db, _job(alert_id), adapter=fake)

    row = proposer_row(db, alert_id)
    assert (row["result"], row["stopped_by"]) == (None, "schema")
    assert len(fake.calls) == 2  # the one repair round, never a third call, never the verifier
    assert (
        'source="mitre_reference"' in fake.calls[0]["user"]
    )  # the section was in what the model saw
    assert triage_status(db, alert_id) == "unavailable"
