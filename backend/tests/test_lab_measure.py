"""P14-T11 / DEC-213, spec §6 - ② computed and not written (`tier2.investigate.evaluate_case`), and the lab
measurement tool (`eval/lab_measure.py`).

Two halves.

**`evaluate_case`.** It runs `SELECT`s only and returns what the job would write; `run_investigate_job` is
that evaluation plus its writes (the existing tests of the job are untouched and still pass). With `as_of`
the dossier keeps only the rows created strictly before it in block 6 (the tier-1 audit rows) and block 8
(the notes and the previous ② run), and the RAG arm reads the newest lookup of the case created before it.
Why (ruling 1): a tier-2 note, or an earlier ② answer, written after the escalation would hand the human's
conclusion to both arms and hide the RAG's effect.

**The tool.** `measure` scores ① and ② against the hand labels with the RAG off and on; `calibrate` scores
the stored rerank of `kb` runs. The pure parts (the truth rule, the statistics, the leak test, the
calibration table) are tested without a database; the rest runs on one scratch lab, a scratch database of
this module's own (`scratch_database`), built once: two runs, a knowledge base, eight alerts, four cases,
their lookups, and a fake model that answers by what the prompt shows. Nothing here calls a model or Voyage;
no test prints a DSN.
"""

from __future__ import annotations

import dataclasses
import itertools
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import pytest
from app.infra import config
from app.infra.jobs import Job
from app.llm import builder as B
from app.security import wrap
from app.tier2 import dossier as dossier_mod
from app.tier2 import investigate as tier2_investigate
from app.tier2 import investigation_view
from psycopg import sql
from psycopg.types.json import Jsonb

from tests.fakes.llm import FakeLLM
from tests.rag_data import add_entry
from tests.scratch_db import scratch_database
from tests.test_investigate import (
    _investigate_v3,
    _make_case,
    _make_head,
    _make_user,
)
from tests.test_triage_rag import history_json

#: Hour zero of every window this module lays: far enough in the past that an alert another test inserts
#: with the default `received_at` (now) is never inside one.
T0 = datetime(2026, 10, 20, 8, 0, tzinfo=UTC)


def at(hours: float) -> datetime:
    return T0 + timedelta(hours=hours)


#: An `as_of` after everything a test inserts.
FUTURE = datetime(2099, 1, 1, tzinfo=UTC)


_LLM_ENV = {
    "LLM_MODEL_PROPOSER": "fake-deepseek",
    "LLM_MODEL_VERIFIER": "fake-deepseek",
    "LLM_PRICE_IN_PER_M": "0.27",
    "LLM_PRICE_OUT_PER_M": "1.10",
    "LLM_MONTHLY_USD_CAP": "30",
    "LLM_THINKING": "disabled",
}


def _cfg(**overrides) -> config.Config:
    """A Config for direct calls: the LLM on, prices set, no DSN on it."""
    base = dataclasses.replace(
        config.Config(),
        LLM_MODEL_PROPOSER="fake-deepseek",
        LLM_MODEL_VERIFIER="fake-deepseek",
        LLM_PRICE_IN_PER_M=0.27,
        LLM_PRICE_OUT_PER_M=1.10,
        DATABASE_URL_OWNER="",
        TEST_DATABASE_URL="",
    )
    return dataclasses.replace(base, **overrides)


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("labmeasure") as dsn:
        yield dsn


def _connect(dsn) -> psycopg.Connection:
    return psycopg.connect(dsn)


def _counts(conn: psycopg.Connection) -> dict[str, int]:
    """The row count of every table of the public schema: what 'wrote nothing' is measured on."""
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY 1"
        )
    ]
    return {
        table: conn.execute(
            sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))
        ).fetchone()[0]
        for table in tables
    }


_LOG = "sshd[411]: Accepted password for user1 from 203.0.113.9 port 4000 ssh2"
_QUOTE_OK = "Accepted password for user1"

_seq = itertools.count()


def _new_case(dsn, *, log: str = _LOG) -> tuple[str, str, str]:
    """A committed case with one head: `(user_id, case_id, head_alert_id)`."""
    with _connect(dsn) as conn:
        user = _make_user(conn)
        case_id = _make_case(conn, user, title=f"labmeasure-{next(_seq)}")
        head = _make_head(conn, case_id, user, raw_log=log)
        conn.commit()
    return user, case_id, head


def _put_lookup(
    conn: psycopg.Connection,
    subject_kind: str,
    subject_id: str,
    created_at: datetime,
    *,
    status: str = "ok",
    matches: list[dict] | None = None,
    failure_kind: str | None = None,
    ranked: list[dict] | None = None,
    total: int = 0,
) -> uuid.UUID:
    lookup_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches,"
        " failure_kind, ranked, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            lookup_id,
            subject_kind,
            subject_id,
            status,
            Jsonb(history_json(total)),
            Jsonb(matches or []),
            failure_kind,
            None if ranked is None else Jsonb(ranked),
            created_at,
        ),
    )
    return lookup_id


def _entry_match(entry_id: str, content: str, score: float, level: str = "giong") -> dict:
    import hashlib

    return {
        "entry_id": entry_id,
        "level": level,
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "score": score,
    }


def _entry(conn: psycopg.Connection, content: str, **fields) -> str:
    return add_entry(conn, content=content, **fields)


def _put_run(conn: psycopg.Connection, case_id: str, created_at: datetime, summary: str) -> None:
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt,"
        " user_message, result, created_at) VALUES (%s, 'investigate', 'case', %s, 's', 'u', %s, %s)",
        (str(uuid.uuid4()), case_id, Jsonb({"summary": summary}), created_at),
    )


def _put_event(conn: psycopg.Connection, event_type: str, alert_id: str, user: str, when) -> None:
    conn.execute(
        "INSERT INTO audit_events (event_type, subject_id, actor_id, actor_role, created_at)"
        " VALUES (%s, %s, %s, 'analyst', %s)",
        (event_type, alert_id, user, when),
    )


def _put_note(conn: psycopg.Connection, case_id: str, user: str, body: str, when) -> None:
    conn.execute(
        "INSERT INTO case_notes (case_id, author_id, body, created_at) VALUES (%s, %s, %s, %s)",
        (case_id, user, body, when),
    )


def _evidence(head: str, quote: str = _QUOTE_OK) -> list[dict]:
    return [{"alert_id": head, "quote": quote, "why": "w"}]


# ═══════════════════════════════════════════════════════════════════════════════════════════
# evaluate_case
# ═══════════════════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
def test_evaluate_case_writes_nothing(scratch_dsn):
    """It runs SELECTs only: inside a READ ONLY transaction the server would refuse a write, and no table
    gains or loses a row."""
    _user, case_id, head = _new_case(scratch_dsn)
    with _connect(scratch_dsn) as conn:
        entry = _entry(conn, "# entry\n\nsummary")
        _put_lookup(
            conn,
            "case",
            case_id,
            at(0),
            matches=[_entry_match(entry, "# entry\n\nsummary", 0.8)],
        )
        conn.commit()

    fake = FakeLLM(responses=[_investigate_v3(evidence=_evidence(head))])
    with _connect(scratch_dsn) as conn:
        conn.execute("SET TRANSACTION READ ONLY")
        before = _counts(conn)
        ev = tier2_investigate.evaluate_case(
            conn, case_id, adapter=fake, cfg=_cfg(), rag=True, as_of=FUTURE
        )
        after = _counts(conn)

    assert ev is not None and ev.outcome == "ok"
    assert len(fake.calls) == 1
    assert after == before


@pytest.mark.db
def test_evaluate_case_of_a_case_that_does_not_exist_is_none(scratch_dsn):
    with _connect(scratch_dsn) as conn:
        assert (
            tier2_investigate.evaluate_case(
                conn, str(uuid.uuid4()), adapter=FakeLLM(), cfg=_cfg(), rag=False
            )
            is None
        )


@pytest.mark.db
@pytest.mark.parametrize(
    ("rag", "verified"),
    [(True, True), (False, True), (True, False)],
    ids=["rag-on-verified", "rag-off-verified", "rag-on-no-verified-evidence"],
)
def test_evaluate_case_result_is_the_jobs(scratch_dsn, monkeypatch, rag, verified):
    """The job is the evaluation plus its writes: what `evaluate_case` returns for a case is what
    `run_investigate_job` stores for it (the result, the evidence check, the warnings, the lookup, the
    usage), and `held_by` / `model_conclusion` are what the investigation view reads of that row."""
    for key, value in _LLM_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("RAG_ENABLED", "true" if rag else "false")
    _user, case_id, head = _new_case(scratch_dsn)
    content = "# entry\n\nsummary of an approved case"
    with _connect(scratch_dsn) as conn:
        entry = _entry(conn, content)
        _put_lookup(conn, "case", case_id, at(0), matches=[_entry_match(entry, content, 0.8)])
        conn.commit()
    answer = _investigate_v3(
        evidence=_evidence(head) if verified else _evidence(head, "no such text")
    )

    with _connect(scratch_dsn) as conn:
        ev = tier2_investigate.evaluate_case(
            conn, case_id, adapter=FakeLLM(responses=[answer]), cfg=config.load(), rag=rag
        )
    job = Job(job_id=8_100_000 + next(_seq), job_type="investigate", subject_id=case_id, attempts=1)
    with _connect(scratch_dsn) as conn:
        tier2_investigate.run_investigate_job(conn, job, adapter=FakeLLM(responses=[answer]))
        conn.commit()
        row = conn.execute(
            "SELECT result, evidence_check, citation_warnings, injection_findings, rag_lookup_id,"
            " input_tokens, output_tokens, stopped_by FROM llm_runs WHERE subject_id = %s"
            " AND pipeline = 'investigate'",
            (case_id,),
        ).fetchone()

    result, evidence_check, warnings, findings, lookup_id, tokens_in, tokens_out, stopped_by = row
    assert ev is not None and ev.outcome == "ok" and stopped_by is None
    assert ev.result == result
    assert ev.evidence_check == evidence_check
    assert ev.citation_warnings == warnings
    assert ev.injection_findings == findings
    assert ev.rag_lookup_id == lookup_id
    assert (ev.rag_lookup_id is not None) is rag
    assert (ev.usage["prompt_tokens"], ev.usage["completion_tokens"]) == (tokens_in, tokens_out)
    assert (
        ev.model_conclusion
        == investigation_view.model_conclusion(evidence_check)
        == "confirmed_incident"
    )
    assert ev.final_conclusion == result["suggested_conclusion"]
    assert ev.held_by == investigation_view.held_by(evidence_check)
    if verified:
        assert ev.final_conclusion == "confirmed_incident" and ev.held_by == []
    else:
        assert ev.final_conclusion == "need_more_data"
        assert ev.held_by == ["no_verified_evidence"]


@pytest.mark.db
def test_evaluate_case_without_the_switch_reads_no_lookup(scratch_dsn):
    """`rag=False`: the stored lookup is neither read nor named, and its section is not in the prompt."""
    _user, case_id, head = _new_case(scratch_dsn)
    content = "# entry\n\nsummary of an approved case"
    with _connect(scratch_dsn) as conn:
        entry = _entry(conn, content)
        _put_lookup(conn, "case", case_id, at(0), matches=[_entry_match(entry, content, 0.8)])
        conn.commit()
    fake = FakeLLM(responses=[_investigate_v3(evidence=_evidence(head))])
    with _connect(scratch_dsn) as conn:
        ev = tier2_investigate.evaluate_case(conn, case_id, adapter=fake, cfg=_cfg(), rag=False)
    assert ev.rag_lookup_id is None and ev.rag_not_applied is None
    assert B.HEADING_LEARNED not in fake.calls[0]["user"]


@pytest.mark.db
def test_as_of_keeps_only_the_rows_before_it_in_blocks_6_and_8(scratch_dsn):
    """Block 6 (the tier-1 audit rows) and block 8 (the notes, the previous ② run) keep a row only when
    it was created STRICTLY before `as_of`: the row at that very instant and every later one are out.
    Without `as_of` all of them are in."""
    user, case_id, head = _new_case(scratch_dsn)
    cut = at(5)
    with _connect(scratch_dsn) as conn:
        _put_event(conn, "alert.acknowledged", head, user, cut - timedelta(minutes=7))
        _put_event(conn, "tier1.decided", head, user, cut)
        _put_event(conn, "tier1.escalated", head, user, cut + timedelta(minutes=9))
        _put_note(conn, case_id, user, "NOTE-BEFORE", cut - timedelta(minutes=3))
        _put_note(conn, case_id, user, "NOTE-AT", cut)
        _put_note(conn, case_id, user, "NOTE-AFTER", cut + timedelta(minutes=3))
        _put_run(conn, case_id, cut - timedelta(minutes=5), "RUN-BEFORE")
        _put_run(conn, case_id, cut + timedelta(minutes=5), "RUN-AFTER")
        conn.commit()

    nonce = "ab" * 8
    with _connect(scratch_dsn) as conn:
        cfg = _cfg()
        cut_text = wrap.strip_nonce(
            dossier_mod.build(conn, case_id, nonce=nonce, cfg=cfg, as_of=cut).text, nonce
        )
        all_text = wrap.strip_nonce(
            dossier_mod.build(conn, case_id, nonce=nonce, cfg=cfg).text, nonce
        )

    for kept in ("alert.acknowledged", "NOTE-BEFORE"):
        assert kept in cut_text and kept in all_text
    for dropped in ("tier1.decided", "tier1.escalated", "NOTE-AT", "NOTE-AFTER"):
        assert dropped not in cut_text
        assert dropped in all_text
    # the previous run is the newest one BEFORE as_of; without as_of it is the newest of all
    assert "RUN-BEFORE" in cut_text and "RUN-AFTER" not in cut_text
    assert "RUN-AFTER" in all_text and "RUN-BEFORE" not in all_text


@pytest.mark.db
def test_as_of_changes_only_blocks_6_and_8(scratch_dsn):
    """A case with nothing created after `as_of` has the dossier it has without it, byte for byte."""
    user, case_id, head = _new_case(scratch_dsn)
    with _connect(scratch_dsn) as conn:
        _put_event(conn, "alert.acknowledged", head, user, at(1))
        _put_note(conn, case_id, user, "NOTE-EARLY", at(1))
        conn.commit()
    nonce = "cd" * 8
    with _connect(scratch_dsn) as conn:
        cfg = _cfg()
        plain = dossier_mod.build(conn, case_id, nonce=nonce, cfg=cfg)
        cut = dossier_mod.build(conn, case_id, nonce=nonce, cfg=cfg, as_of=FUTURE)
    assert cut.text == plain.text


@pytest.mark.db
def test_as_of_reaches_the_prompt_of_the_evaluation(scratch_dsn):
    user, case_id, head = _new_case(scratch_dsn)
    with _connect(scratch_dsn) as conn:
        _put_note(conn, case_id, user, "NOTE-BEFORE-THE-RUN", at(4))
        _put_note(conn, case_id, user, "NOTE-AFTER-THE-RUN", at(6))
        conn.commit()
    fake = FakeLLM(responses=[_investigate_v3(evidence=_evidence(head))])
    with _connect(scratch_dsn) as conn:
        tier2_investigate.evaluate_case(
            conn, case_id, adapter=fake, cfg=_cfg(), rag=False, as_of=at(5)
        )
    prompt = fake.calls[0]["user"]
    assert "NOTE-BEFORE-THE-RUN" in prompt and "NOTE-AFTER-THE-RUN" not in prompt


@pytest.mark.db
def test_the_rag_arm_reads_the_newest_lookup_before_as_of(scratch_dsn):
    """A lookup created after `as_of` is not there: the newest one before it decides. Without `as_of` the
    newest of all does (today's job): here a `failed` one, which gives the notice and no section."""
    _user, case_id, head = _new_case(scratch_dsn)
    content = "# approved\n\nan approved entry"
    with _connect(scratch_dsn) as conn:
        entry = _entry(conn, content)
        good = _put_lookup(
            conn, "case", case_id, at(1), matches=[_entry_match(entry, content, 0.8)]
        )
        _put_lookup(conn, "case", case_id, at(3), status="failed", failure_kind="rate_limit")
        conn.commit()

    def run(**kwargs):
        fake = FakeLLM(responses=[_investigate_v3(evidence=_evidence(head))])
        with _connect(scratch_dsn) as conn:
            ev = tier2_investigate.evaluate_case(
                conn, case_id, adapter=fake, cfg=_cfg(), rag=True, **kwargs
            )
        return ev, fake.calls[0]["user"]

    ev, prompt = run(as_of=at(2))
    assert ev.rag_lookup_id == good and ev.rag_not_applied is None
    assert B.HEADING_LEARNED in prompt and "an approved entry" in prompt

    ev, prompt = run()
    assert ev.rag_lookup_id is None and ev.rag_not_applied == "rate_limit"
    assert B.HEADING_LEARNED not in prompt
    assert "rag_not_applied:rate_limit" in (ev.citation_warnings or [])


@pytest.mark.db
def test_a_newer_failed_lookup_before_as_of_hides_an_older_good_one(scratch_dsn):
    """The newest lookup decides, as in the product: a newer `failed` hides an older good one."""
    _user, case_id, head = _new_case(scratch_dsn)
    content = "# approved\n\nan approved entry"
    with _connect(scratch_dsn) as conn:
        entry = _entry(conn, content)
        _put_lookup(conn, "case", case_id, at(1), matches=[_entry_match(entry, content, 0.8)])
        _put_lookup(conn, "case", case_id, at(2), status="failed", failure_kind="timeout")
        conn.commit()
    fake = FakeLLM(responses=[_investigate_v3(evidence=_evidence(head))])
    with _connect(scratch_dsn) as conn:
        ev = tier2_investigate.evaluate_case(
            conn, case_id, adapter=fake, cfg=_cfg(), rag=True, as_of=at(3)
        )
    assert ev.rag_lookup_id is None and ev.rag_not_applied == "timeout"
    assert B.HEADING_LEARNED not in fake.calls[0]["user"]
