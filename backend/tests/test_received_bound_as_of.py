"""P14 final fix wave, C1 (DEC-213, spec §6) - what ① and ② could have known at the subject's first look.

`eval/lab_measure.py` scores ① and ② on the alerts of a test run after the run is over. Until this wave ①'s
burst count and correlation section, and ②'s block 5, were read at measurement time: an alert received after
the subject's first look (a later stage of the same attack, the rest of the same burst) was counted, listed
and sampled, which production ① never saw. `as_of` closes that, as it already did for ②'s blocks 6 and 8:

* `evaluate_alert(..., as_of=)` bounds `BURST_COUNT_SQL` and both correlation queries by
  `received_at < as_of`, and its RAG-on arm reads the newest lookup created before `as_of`
  (`rag.lookup.latest_lookup(before=)`, as ② does);
* `tier2.dossier.build(..., as_of=)` bounds block 5's two queries the same way;
* **`as_of=None` is today's behaviour, byte for byte**: the same SQL text, the same parameters, the same
  prompts. The existing tests of the burst query, the correlation module and the dossier are untouched and
  pin that; the tests here pin the `None` path again, beside the new one.

Every test inserts its own rows under a tag of its own (agent, user and source address), so no alert another
test committed is inside its window. Nothing here calls a model or Voyage.
"""

from __future__ import annotations

import dataclasses
import itertools
from datetime import UTC, datetime, timedelta

import pytest
from app.domain import correlation
from app.llm import builder as B
from app.security import wrap
from app.tier1 import triage as triage_module
from app.tier2 import dossier as dossier_mod
from app.tier2 import investigate as tier2_investigate

from tests.fakes.llm import FakeLLM
from tests.rag_data import add_entry
from tests.test_investigate import _add_head, _investigate_v3, _make_case, _make_user
from tests.test_lab_measure import _cfg as _lab_cfg
from tests.test_lab_measure import _entry_match, _evidence, _put_lookup
from tests.test_triage_job import (
    _FP_ALERT,
    _VERIFIER_FP_AGREE,
    _fp_proposal,
    _RecordingLLM,
    _seed_alert,
)

pytestmark = pytest.mark.db

#: The subject's first look; a neighbour received before it is something production ① saw, after it is not.
CUT = datetime(2026, 8, 16, 18, 0, 0, tzinfo=UTC)
BEFORE = CUT - timedelta(minutes=10)
AFTER = CUT + timedelta(minutes=10)

_tags = itertools.count()


def _key(tag: str) -> dict:
    """The columns a window or a burst is keyed on, unique to one test: no other row is in its window."""
    n = next(_tags)
    return {
        "agent_name": f"asof-{tag}-{n}",
        "alert_user": f"asof-user-{tag}-{n}",
        "srcip": f"10.77.{n % 250}.{(n * 7) % 250 + 1}",
    }


def _seed(db, *, received: datetime, **fields) -> str:
    return _seed_alert(db, received_at=received, **fields)


def _subject_of(db, alert_id: str) -> triage_module._Subject:
    row = db.execute(
        "SELECT agent_name, alert_user, srcip, alert_time FROM alerts WHERE alert_id = %s",
        (alert_id,),
    ).fetchone()
    return triage_module._Subject(alert_id, *row)


# ── the correlation queries ─────────────────────────────────────────────────────────────────


def test_the_correlation_queries_are_unchanged_without_as_of_and_bounded_with_it():
    subject = triage_module._Subject("a-1", "agent", "user", "10.0.0.1", CUT)
    for build in (correlation.rows_query, correlation.samples_query):
        text, params = build(subject)
        assert (
            "received_at" not in text and "as_of" not in params
        )  # today's statement and parameters
        assert build(subject, as_of=None) == (text, params)
        bounded_text, bounded_params = build(subject, as_of=CUT)
        assert bounded_text.count("received_at < %(as_of)s") == 1
        assert bounded_params == {**params, "as_of": CUT}
        # the bound is the only difference
        assert bounded_text.replace("\n          AND received_at < %(as_of)s", "") == text


def test_a_neighbour_received_after_as_of_is_not_counted_listed_or_sampled_by_tier_1(db):
    key = _key("corr")
    subject = _seed(db, received=BEFORE, **key, **_FP_ALERT)
    _seed(db, received=BEFORE, rule_id="91001", description="EARLY-STAGE", **key)
    _seed(db, received=AFTER, rule_id="91002", description="LATE-STAGE", **key)
    subject_row = _subject_of(db, subject)

    plain = correlation.summarize_for_prompt(db, subject_row)
    assert {row.rule_id for row in plain.rows} >= {"91001", "91002"}  # today: both
    assert {s["description"] for s in plain.samples} >= {"EARLY-STAGE", "LATE-STAGE"}

    cut = correlation.summarize_for_prompt(db, subject_row, as_of=CUT)
    assert {row.rule_id for row in cut.rows} == {"91001"}
    assert {s["description"] for s in cut.samples} == {"EARLY-STAGE"}
    assert sum(row.alert_count for row in cut.rows) == 1  # not counted
    # an `as_of` after everything is today's summary
    assert (
        correlation.summarize_for_prompt(db, subject_row, as_of=AFTER + timedelta(days=1)) == plain
    )


# ── the burst count ─────────────────────────────────────────────────────────────────────────


def test_burst_count_with_as_of_counts_only_alerts_received_before_it(db):
    cfg = _lab_cfg(DEDUP_ENABLED=False)
    key = _key("burst")
    burst = dict(key, rule_id="91003", first_seen_at=CUT, last_seen_at=CUT)
    first = _seed(db, received=BEFORE, **burst)
    _seed(db, received=BEFORE + timedelta(minutes=1), **burst)
    _seed(db, received=AFTER, **burst)
    _seed(db, received=AFTER + timedelta(minutes=1), **burst)

    assert triage_module.burst_count(db, first, cfg) == 4  # today: the whole burst
    assert triage_module.burst_count(db, first, cfg, as_of=CUT) == 2
    assert triage_module.burst_count(db, first, cfg, as_of=None) == 4
    # strictly before: an alert received at the very instant is out
    at_cut = _seed(db, received=CUT, **burst)
    assert (
        triage_module.burst_count(db, at_cut, cfg, as_of=CUT) == 2
    )  # itself is out too, by the bound
    assert triage_module.burst_count(db, first, cfg, as_of=CUT + timedelta(seconds=1)) == 3


def test_the_burst_query_with_as_of_is_one_more_bound_parameter_and_still_uses_an_index(db):
    alert = _seed(db, received=BEFORE)
    statement, params = triage_module.burst_count_query(alert, _lab_cfg())
    assert statement == triage_module.BURST_COUNT_SQL and len(params) == 2  # today's, unchanged
    bounded, bounded_params = triage_module.burst_count_query(alert, _lab_cfg(), as_of=CUT)
    assert bounded.count("%s") == len(bounded_params) == 3 and bounded_params[2] == CUT
    assert bounded.startswith(triage_module.BURST_COUNT_SQL)
    assert alert not in bounded
    db.execute("SET LOCAL enable_seqscan = off")
    plan = "\n".join(r[0] for r in db.execute("EXPLAIN " + bounded, bounded_params).fetchall())
    assert "Seq Scan on alerts" not in plan and "ix_alerts_" in plan, plan


# ── evaluate_alert ──────────────────────────────────────────────────────────────────────────


def _evaluate(db, alert_id, *, rag=False, **kwargs):
    """`(evaluation, the proposer's user message)` with DEDUP off (the trial's setting)."""
    fake = _RecordingLLM(responses=[_fp_proposal(2), _VERIFIER_FP_AGREE])
    switches = dataclasses.replace(triage_module.DEPLOYED, rag=rag)
    ev = triage_module.evaluate_alert(
        db, alert_id, adapter=fake, cfg=_lab_cfg(DEDUP_ENABLED=False), switches=switches, **kwargs
    )
    return ev, fake.calls[0]["user"]


def test_tier_1_as_of_shows_the_burst_and_the_correlation_as_they_were_at_first_look(db):
    """A burst of four with the subject first: two alerts of it before the first look (itself and one more), two
    after; and two later stages of the attack, with their raw logs, inside the +-2 h window. At the first look ① sees
    2, no later stage and no later raw log; read now it sees 4 and all of them."""
    key = _key("tier1")
    burst = dict(key, rule_id="91004", first_seen_at=CUT, last_seen_at=CUT, **_FP_ALERT)
    subject = _seed(db, received=BEFORE, **burst)
    _seed(db, received=BEFORE + timedelta(minutes=1), **burst)
    _seed(db, received=AFTER, **burst)
    _seed(db, received=AFTER + timedelta(minutes=1), **burst)
    _seed(
        db, received=BEFORE, rule_id="91005", description="EARLY-STAGE", raw_log="EARLY-RAW", **key
    )
    _seed(db, received=AFTER, rule_id="91006", description="LATE-STAGE", raw_log="LATE-RAW", **key)

    now_ev, now_prompt = _evaluate(db, subject)
    assert now_ev.facts["occurrence_count"] == 4
    assert "occurrence_count: 4" in now_prompt
    assert "LATE-RAW" in now_prompt and "EARLY-RAW" in now_prompt

    ev, prompt = _evaluate(db, subject, as_of=CUT)
    assert ev.facts["occurrence_count"] == 2
    assert "occurrence_count: 2" in prompt and "occurrence_count: 4" not in prompt
    assert "EARLY-RAW" in prompt and "LATE-RAW" not in prompt
    assert "91006" not in prompt  # not even as a row of the correlation summary
    assert ev.built.prompt.user == prompt

    # `as_of=None` is the call without it
    none_ev, none_prompt = _evaluate(db, subject, as_of=None)
    assert none_ev.facts == now_ev.facts
    assert wrap.strip_nonce(none_prompt, none_ev.built.prompt.nonce) == wrap.strip_nonce(
        now_prompt, now_ev.built.prompt.nonce
    )


def test_a_decision_table_rule_that_needs_a_small_burst_holds_at_first_look_and_not_later(db):
    """`sbf-1` holds below 50: a burst of 60 received after the first look is not the burst ① saw."""
    key = _key("rule")
    burst = dict(key, rule_id="91007", first_seen_at=CUT, last_seen_at=CUT, **_FP_ALERT)
    subject = _seed(db, received=BEFORE, **burst)
    for i in range(59):
        _seed(db, received=AFTER + timedelta(seconds=i), **burst)
    assert triage_module.burst_count(db, subject, _lab_cfg(DEDUP_ENABLED=False)) == 60
    ev, _prompt = _evaluate(db, subject, as_of=CUT)
    assert ev.facts["occurrence_count"] == 1


def _entry(db, content: str) -> str:
    return add_entry(db, content=content)


def test_the_rag_on_arm_of_tier_1_reads_the_newest_lookup_before_as_of(db):
    """A good lookup before the first look and a failed one after: ① saw the good one. Without `as_of` the
    newest decides (the failed one: the notice, no section)."""
    key = _key("rag-good")
    content = "# approved\n\nan approved entry called good-before"
    alert = _seed(db, received=BEFORE, **key, **_FP_ALERT)
    entry = _entry(db, content)
    good = _put_lookup(
        db,
        "alert",
        alert,
        BEFORE + timedelta(minutes=1),
        matches=[_entry_match(entry, content, 0.8)],
    )
    _put_lookup(db, "alert", alert, AFTER, status="failed", failure_kind="rate_limit")

    ev, prompt = _evaluate(db, alert, rag=True, as_of=CUT)
    assert ev.rag_lookup_id == good
    assert B.HEADING_LEARNED in prompt and "good-before" in prompt
    assert not any(w.startswith("rag_not_applied") for w in ev.built.warnings)

    ev, prompt = _evaluate(db, alert, rag=True)
    assert ev.rag_lookup_id is None and B.HEADING_LEARNED not in prompt
    assert "rag_not_applied:rate_limit" in ev.built.warnings


def test_a_lookup_created_after_as_of_is_not_there_for_tier_1(db):
    key = _key("rag-late")
    content = "# approved\n\nan approved entry called late-lookup"
    alert = _seed(db, received=BEFORE, **key, **_FP_ALERT)
    entry = _entry(db, content)
    _put_lookup(db, "alert", alert, AFTER, matches=[_entry_match(entry, content, 0.8)])

    ev, prompt = _evaluate(
        db, alert, rag=True, as_of=CUT
    )  # no lookup yet: today's prompt, no notice
    assert ev.rag_lookup_id is None and B.HEADING_LEARNED not in prompt
    assert not any(w.startswith("rag_not_applied") for w in ev.built.warnings)

    ev, prompt = _evaluate(db, alert, rag=True)
    assert ev.rag_lookup_id is not None and "late-lookup" in prompt


def test_a_failed_lookup_before_as_of_is_the_notice_and_hides_an_older_good_one_for_tier_1(db):
    key = _key("rag-failed")
    content = "# approved\n\nan approved entry called hidden"
    alert = _seed(db, received=BEFORE, **key, **_FP_ALERT)
    entry = _entry(db, content)
    _put_lookup(db, "alert", alert, BEFORE, matches=[_entry_match(entry, content, 0.8)])
    _put_lookup(
        db, "alert", alert, BEFORE + timedelta(minutes=2), status="failed", failure_kind="timeout"
    )
    _put_lookup(db, "alert", alert, AFTER, matches=[_entry_match(entry, content, 0.8)])

    ev, prompt = _evaluate(db, alert, rag=True, as_of=CUT)
    assert ev.rag_lookup_id is None and B.HEADING_LEARNED not in prompt
    assert "rag_not_applied:timeout" in ev.built.warnings


# ── ② block 5 ───────────────────────────────────────────────────────────────────────────────


def _case(db, **key) -> tuple[str, str, str]:
    user = _make_user(db)
    case_id = _make_case(db, user)
    head = _seed(db, received=BEFORE, **key)
    _add_head(db, case_id, head, user)
    return user, case_id, head


def test_block_5_as_of_leaves_out_a_neighbour_received_after_it(db):
    key = _key("block5")
    _user, case_id, _head = _case(db, **key)
    _seed(
        db,
        received=BEFORE,
        rule_id="91008",
        description="EARLY-NEIGHBOUR",
        raw_log="EARLY-RAW",
        **key,
    )
    _seed(
        db, received=AFTER, rule_id="91009", description="LATE-NEIGHBOUR", raw_log="LATE-RAW", **key
    )
    nonce = "ef" * 8
    cfg = _lab_cfg()

    plain = wrap.strip_nonce(dossier_mod.build(db, case_id, nonce=nonce, cfg=cfg).text, nonce)
    cut = wrap.strip_nonce(
        dossier_mod.build(db, case_id, nonce=nonce, cfg=cfg, as_of=CUT).text, nonce
    )

    for marker in ("EARLY-RAW", "91008"):
        assert marker in plain and marker in cut
    for marker in ("LATE-RAW", "91009"):
        assert marker in plain  # today's block 5 holds the later stage
        assert marker not in cut  # as of the first look it was not received yet
    # nothing received after `as_of`, nothing different: the bound is the whole change
    after_all = dossier_mod.build(
        db, case_id, nonce=nonce, cfg=cfg, as_of=AFTER + timedelta(days=1)
    )
    assert wrap.strip_nonce(after_all.text, nonce) == plain


def test_block_5_without_as_of_runs_the_statements_it_always_ran(db):
    for text in (dossier_mod._CORRELATION_ROWS_SQL, dossier_mod._CORRELATION_SAMPLES_SQL):
        assert "received_at" not in text
    for text in (
        dossier_mod._CORRELATION_ROWS_BEFORE_SQL,
        dossier_mod._CORRELATION_SAMPLES_BEFORE_SQL,
    ):
        assert text.count("received_at < %(as_of)s") == 1


def test_the_prompt_of_evaluate_case_as_of_holds_no_later_stage(db):
    key = _key("block5-eval")
    _user, case_id, head = _case(db, **key)
    _seed(db, received=BEFORE, rule_id="91010", description="EARLY-NEIGHBOUR", **key)
    _seed(
        db, received=AFTER, rule_id="91011", description="LATE-NEIGHBOUR", raw_log="LATE-RAW", **key
    )
    fake = FakeLLM(responses=[_investigate_v3(evidence=_evidence(head))])
    tier2_investigate.evaluate_case(db, case_id, adapter=fake, cfg=_lab_cfg(), rag=False, as_of=CUT)
    prompt = fake.calls[0]["user"]
    assert "91010" in prompt and "91011" not in prompt and "LATE-RAW" not in prompt
    fake = FakeLLM(responses=[_investigate_v3(evidence=_evidence(head))])
    tier2_investigate.evaluate_case(db, case_id, adapter=fake, cfg=_lab_cfg(), rag=False)
    assert "91011" in fake.calls[0]["user"]  # without it, today's prompt
