"""P12-T02 / DEC-208 item 4 — for an alert SOAR enriched, ①'s occurrence count is unknown: `None`.

SOAR sends one representative per `dedup_key`, so nothing here knows how many alerts the case holds.
A count of `1` would be a guess that lets `occurrence_lt: 50` rules fire; the burst count (DEC-165)
would count only the representatives that arrived. So the facts ① works from carry `None`:

1. **The decision tables.** `kb.lookup.rule_matches` already makes a rule whose fact is absent not
   match, so none of the nine `occurrence_lt: 50` `false_positive` rules can hold on an unknown count.
2. **The prompt.** The proposer and verifier prompts say `occurrence_count: không rõ`, through the
   builder: `fact()` still refuses a free string, and the phrase is one `TEMPLATE_CONSTANTS` entry.
3. **The gate.** A ① `false_positive` whose cited rule cannot hold is forced to `needs_review` by
   step 4. Step 2 compares the model's integer `structured_basis.occurrence_count` only with a
   known count (DEC-209 item 2): with the fact `None` it has nothing to compare, so the only thing
   that forces such an answer is step 4 and the hallucination flag stays false; a known count that
   the model gets wrong is still flagged.
4. **Where `None` comes from.** From the alert's own document (`raw_payload` carries SOAR's
   `enrichment` block), read in `tier1/triage._load`, so `evaluate_alert`, the job and the evaluation
   harness's `b1_facts` (which shares `_load`) see the same value whatever the switches say. An alert
   with no such block keeps the row's count, or the burst count with `DEDUP_ENABLED=false`, as before.

The model is the fake adapter; the tests that need rows run on the test database inside the `db`
transaction.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from pathlib import Path

import pytest
from app.infra import config
from app.infra.jobs import Job
from app.kb import lookup as kb
from app.llm import builder as B
from app.llm import triage as T
from app.security import gate
from app.security import linter as L
from app.tier1 import triage as tier1

from tests.fakes.llm import TRIAGE_V2_FALSE_POSITIVE, FakeLLM
from tests.soar_payloads import (
    edit,
    llm_cfg,
    mw03,
    receive_and_run,
    stream_config,
    ti,
    triage_input,
    with_wazuh_id,
)

NONCE = "0123456789abcdef"


# ---------------------------------------------------------------------------
# 1 · the decision tables
# ---------------------------------------------------------------------------


def _tables() -> list[tuple[str, kb.DecisionTable]]:
    found = [(c.value, kb.get_decision_table(c.value)) for c in B.Category]
    return [(category, table) for category, table in found if table is not None]


def _occurrence_lt_rules() -> list[tuple[str, kb.Rule]]:
    return [
        (category, rule)
        for category, table in _tables()
        for rule in table.rules
        if "occurrence_lt" in rule.condition
    ]


def _facts_satisfying(rule: kb.Rule, occurrence: int | None) -> dict:
    """Facts that meet every condition of `rule` but the occurrence one, which is `occurrence`."""
    facts: dict = {"occurrence_count": occurrence}
    for key, value in rule.condition.items():
        if key == "occurrence_lt":
            continue
        if key in ("rule_level_gte", "rule_level_lt"):
            facts["rule_level"] = value if key == "rule_level_gte" else value - 1
        else:
            facts[key] = value[0]
    return facts


def test_there_are_nine_occurrence_lt_rules_and_every_one_is_a_false_positive_of_50() -> None:
    rules = _occurrence_lt_rules()

    assert len(rules) == 9
    assert {rule.action for _, rule in rules} == {"false_positive"}
    assert {rule.condition["occurrence_lt"] for _, rule in rules} == {50}
    assert sorted(rule.id for _, rule in rules) == [
        "bf-1",
        "c2b-1",
        "dex-1",
        "mal-1",
        "pol-1",
        "rec-1",
        "sbf-1",
        "sul-1",
        "web-1",
    ]


@pytest.mark.parametrize(
    "category, rule", _occurrence_lt_rules(), ids=lambda v: getattr(v, "id", v)
)
def test_no_occurrence_lt_rule_matches_an_unknown_count(category: str, rule: kb.Rule) -> None:
    holds_at_one = kb.rule_matches(rule, _facts_satisfying(rule, 1))
    holds_at_49 = kb.rule_matches(rule, _facts_satisfying(rule, 49))
    absent = _facts_satisfying(rule, 1)
    del absent["occurrence_count"]

    assert holds_at_one and holds_at_49  # the control: everything else in the rule is satisfied
    assert kb.rule_matches(rule, _facts_satisfying(rule, 50)) is False
    assert kb.rule_matches(rule, _facts_satisfying(rule, None)) is False
    assert kb.rule_matches(rule, absent) is False


def test_on_no_point_of_the_fact_grid_does_a_false_positive_rule_hold_with_an_unknown_count() -> (
    None
):
    for category, table in _tables():
        false_positives = [rule for rule in table.rules if rule.action == "false_positive"]
        if not false_positives:
            continue
        known = unknown = 0
        for point in kb.fact_grid():
            known += any(kb.rule_matches(rule, point) for rule in false_positives)
            unknown += any(
                kb.rule_matches(rule, {**point, "occurrence_count": None})
                for rule in false_positives
            )
        assert known > 0, category  # the control: the grid does reach the rules
        assert unknown == 0, category


# ---------------------------------------------------------------------------
# 2 · the facts and the prompts
# ---------------------------------------------------------------------------


def test_the_facts_carry_none_and_stay_serialisable() -> None:
    facts = T.build_facts(triage_input(occurrence_count=None), None)

    assert facts["occurrence_count"] is None
    assert json.loads(json.dumps(facts))["occurrence_count"] is None  # `gate_result.facts` is jsonb


@pytest.mark.parametrize("count", [0, 1, 3, 50, 1234])
def test_a_known_count_is_an_int_as_before_and_zero_is_not_unknown(count: int) -> None:
    facts = T.build_facts(triage_input(occurrence_count=count), None)

    assert facts["occurrence_count"] == count and isinstance(facts["occurrence_count"], int)


def _proposer_user(inp: T.TriageInput) -> str:
    facts = T.build_facts(inp, None)
    table = kb.get_decision_table("malware")
    built = T.build_proposer_prompt(
        inp, facts, None, kb.get_playbook("malware"), table, cfg=llm_cfg(), nonce=NONCE
    )
    assert (
        L.lint(built.prompt.user, nonce=NONCE, constants=B.TEMPLATE_CONSTANTS, enums=B.ENUM_VALUES)
        == []
    )
    return built.prompt.user


def test_the_proposer_prompt_says_unknown_in_the_place_of_the_count() -> None:
    user = _proposer_user(triage_input(occurrence_count=None))

    line = next(row for row in user.splitlines() if row.startswith("severity:"))
    assert (
        line
        == "severity: medium · category: malware · occurrence_count: không rõ · risk_band: medium"
    )
    assert not re.search(r"occurrence_count: -?\d", user)


@pytest.mark.parametrize("count", [0, 3, 50])
def test_the_proposer_prompt_of_a_known_count_is_the_one_of_before(count: int) -> None:
    """`0` is a count too: only `None` is "không rõ"."""
    user = _proposer_user(triage_input(occurrence_count=count))

    line = next(row for row in user.splitlines() if row.startswith("severity:"))
    expected = (
        f"severity: medium · category: malware · occurrence_count: {count} · risk_band: medium"
    )
    assert line == expected
    assert "không rõ" not in user


def test_the_verifier_prompt_says_unknown_too() -> None:
    inp = triage_input(occurrence_count=None)
    facts = T.build_facts(inp, None)

    built = T.build_verifier_prompt(
        facts, kb.get_decision_table("malware"), "needs_review", [], cfg=llm_cfg(), nonce=NONCE
    )

    assert "occurrence_count: không rõ" in built.prompt.user
    assert not re.search(r"occurrence_count: -?\d", built.prompt.user)
    assert (
        L.lint(built.prompt.user, nonce=NONCE, constants=B.TEMPLATE_CONSTANTS, enums=B.ENUM_VALUES)
        == []
    )
    known = T.build_verifier_prompt(
        T.build_facts(triage_input(occurrence_count=7), None),
        kb.get_decision_table("malware"),
        "needs_review",
        [],
        cfg=llm_cfg(),
        nonce=NONCE,
    )
    assert "occurrence_count: 7" in known.prompt.user and "không rõ" not in known.prompt.user


def test_the_builder_still_refuses_a_free_string_and_none_as_a_fact() -> None:
    """The unknown is a template constant, not a value `fact()` accepts: nothing was loosened."""
    with pytest.raises(TypeError):
        B.fact("occurrence_count", "không rõ")
    with pytest.raises(TypeError):
        B.fact("occurrence_count", None)
    with pytest.raises(TypeError):
        B.fact("occurrence_count", "3")


def test_the_phrase_is_a_template_constant_and_nothing_wider_is() -> None:
    pb = B.PromptBuilder("system", nonce=NONCE)
    pb.line(B.FACT_OCCURRENCE_UNKNOWN)  # accepted: one constant of the template
    assert B.FACT_OCCURRENCE_UNKNOWN == "occurrence_count: không rõ"
    assert B.FACT_OCCURRENCE_UNKNOWN in B.TEMPLATE_CONSTANTS
    with pytest.raises(ValueError):
        pb.line("occurrence_count: vài chục")  # a look-alike is not
    with pytest.raises(ValueError):
        pb.line("không rõ")
    assert len(B.HEADINGS) == 10 and len(B.SENTENCES) == 9  # the two sets test_builder pins


def test_a_look_alike_of_the_phrase_is_free_text_to_the_linter() -> None:
    user = _proposer_user(triage_input(occurrence_count=None))
    tampered = user.replace("không rõ", "khoảng 3")

    violations = L.lint(tampered, nonce=NONCE, constants=B.TEMPLATE_CONSTANTS, enums=B.ENUM_VALUES)

    assert [v.kind for v in violations] == ["free_text"]


# ---------------------------------------------------------------------------
# 3 · the gate
# ---------------------------------------------------------------------------


def _false_positive(rule: str = "mal-1", *, occurrence: int = 1) -> dict:
    """① says `false_positive` under `mal-1`, its `structured_basis` equal to the facts of `_input`."""
    answer = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    answer["structured_basis"] = {
        "severity": "medium",
        "ioc_reputation": "clean",
        "asset_criticality": "medium",
        "identity_privileged": "false",
        "occurrence_count": occurrence,
        "playbook_rule_applied": rule,
    }
    answer["reasons"][0]["quote"] = "Microsoft Defender: Malware Detected"
    return answer


def _step_4(occurrence: int | None) -> gate.GateState:
    """Gate step 4 on `_false_positive()` and the facts of `_input`, with the rule check ① builds."""
    facts = T.build_facts(triage_input(occurrence_count=occurrence), None)
    rule_check = tier1._make_rule_check(kb.get_decision_table("malware"), facts)
    state = gate.start(_false_positive(), facts, {}, repaired=False)
    gate.step4_fp_policy(state, rule_check)
    return state


def test_step_4_keeps_the_false_positive_when_the_count_is_known_and_small() -> None:
    """The control (DEC-025): every fact is the same but the count."""
    state = _step_4(1)

    assert state.verdict == "false_positive"
    assert state.forced_by == [] and state.missing == [] and state.steps["4"] == "ok"


def test_step_4_forces_the_false_positive_to_needs_review_when_the_count_is_unknown() -> None:
    state = _step_4(None)

    assert state.verdict == "needs_review" and state.proposed_verdict == "false_positive"
    assert state.forced_by == ["step4"]
    assert state.missing == ["playbook_rule"]  # severity, IoC, asset and account all pass
    assert state.warnings == ["rule_does_not_hold"]


def test_step_2_does_not_flag_a_hallucination_for_an_unknown_count() -> None:
    """Step 2 used to read `int(basis["occurrence_count"]) != facts["occurrence_count"]`; with the
    fact `None` that is true for any integer the model writes (the schema makes it an integer), so
    every ① answer on a SOAR alert was flagged `hallucination_flag` and forced at step 2, before
    step 4 was reached. DEC-209 item 2: an unknown count is not compared."""
    facts = T.build_facts(triage_input(occurrence_count=None), None)
    state = gate.start(_false_positive(occurrence=1), facts, {}, repaired=False)

    gate.step2_basis(state)

    assert state.hallucination_flag is False
    assert state.mismatched_fields == [] and state.steps["2"] == "ok"


def _step_2(fact_count: int | None, basis_count: int) -> gate.GateState:
    facts = T.build_facts(triage_input(occurrence_count=fact_count), None)
    state = gate.start(_false_positive(occurrence=basis_count), facts, {}, repaired=False)
    gate.step2_basis(state)
    return state


@pytest.mark.parametrize(
    "fact_count, basis_count",
    [(None, 0), (None, 1), (None, 3), (None, 999), (None, -5)],
)
def test_step_2_takes_any_integer_when_the_count_is_unknown(
    fact_count: None, basis_count: int
) -> None:
    state = _step_2(fact_count, basis_count)

    assert state.steps["2"] == "ok" and state.forced_by == []
    assert state.verdict == "false_positive" and state.hallucination_flag is False


@pytest.mark.parametrize(
    "fact_count, basis_count",
    [(3, 3), (0, 0), (1, 1), (50, 50)],
)
def test_step_2_passes_a_known_count_the_model_got_right(fact_count: int, basis_count: int) -> None:
    state = _step_2(fact_count, basis_count)

    assert state.steps["2"] == "ok" and state.hallucination_flag is False


@pytest.mark.parametrize(
    "fact_count, basis_count",
    [(3, 4), (3, 2), (1, 0), (0, 1), (0, 3), (50, 49), (1, 999)],
)
def test_step_2_still_flags_a_known_count_the_model_got_wrong(
    fact_count: int, basis_count: int
) -> None:
    """The change skips an UNKNOWN count and nothing else. `0` is a count (`if expected:` would let
    `(0, 1)` through), and a wrong one is the hallucination step 2 exists to catch."""
    state = _step_2(fact_count, basis_count)

    assert state.steps["2"] == "mismatch"
    assert state.hallucination_flag is True
    assert state.mismatched_fields == ["occurrence_count"]
    assert state.forced_by == ["step2"] and state.verdict == "needs_review"


# ---------------------------------------------------------------------------
# 4 · on the database: where the `None` comes from
# ---------------------------------------------------------------------------

_FP_ID = mw03()["id"]  # the sample's own Graylog id (DEC-209): ① renders it as it is
_WAZUH_ID = "1789200000.300001"


def fp_candidate(alert_id: str = _FP_ID) -> dict:
    """The Defender sample made into an alert ① may close: level 5 (medium), a `medium` asset in the
    inventory, a `clean` address, an account that is not an admin. It meets every condition of
    `mal-1` but the occurrence one. It keeps the sample's own `gl-…` id unless a test gives it the
    Wazuh shape (`alert_id=`)."""
    doc = mw03(criticality="medium", in_inventory=True)
    if alert_id != doc["id"]:
        with_wazuh_id(doc, alert_id)
    doc["rule"]["level"] = 5
    doc["enrichment"]["ti"] = [ti("clean")]
    return doc


class _FakeComplete(FakeLLM):
    """`FakeLLM` plus the `model` keyword the real adapter's `complete()` takes."""

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        return super().complete(
            system=system, user=user, response_format=response_format, timeout_s=timeout_s
        )


def _verifier(verdict: str = "needs_review") -> dict:
    return {
        "agree": True,
        "structured_only_verdict": verdict,
        "reason": f"Structured facts alone give {verdict}.",
    }


@pytest.fixture
def stream(db, monkeypatch) -> config.Config:
    """The four switches off, the fake model, and no DSN on the config object (its repr prints its
    fields, and a failing assertion must never put a credential in the test output)."""
    cfg = stream_config(monkeypatch)
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    return dataclasses.replace(
        config.load(env_file="/dev/null"),
        DATABASE_URL="",
        DATABASE_URL_OWNER="",
        TEST_DATABASE_URL="",
        WEBHOOK_API_KEY=cfg.WEBHOOK_API_KEY,
        LLM_PRICE_IN_PER_M=0.27,
        LLM_PRICE_OUT_PER_M=1.10,
    )


@pytest.mark.db
def test_a_soar_alert_is_loaded_with_an_unknown_count(db, stream) -> None:
    receive_and_run(db, stream, fp_candidate())

    row = tier1._load(db, _FP_ID)

    assert row is not None
    assert row.occurrence_count is None
    stored = db.execute("SELECT occurrence_count FROM alerts WHERE alert_id = %s", (_FP_ID,))
    assert stored.fetchone() == (1,)  # the column keeps its default; only ①'s reading changed


@pytest.mark.db
@pytest.mark.parametrize(
    "enrichment",
    [
        pytest.param(None, id="a valid block"),
        pytest.param("json-null", id="enrichment: null"),
        pytest.param("not-an-object", id="enrichment: a string"),
        pytest.param("schema-2", id="schema 2.0"),
    ],
)
def test_the_count_is_unknown_whatever_the_block_holds_and_whatever_the_switches_say(
    db, stream, enrichment: str | None
) -> None:
    doc = fp_candidate()
    if enrichment == "json-null":
        doc["enrichment"] = None
    elif enrichment == "not-an-object":
        doc["enrichment"] = "x"
    elif enrichment == "schema-2":
        edit(doc, "enrichment.schema_version", "2.0")
    receive_and_run(db, stream, doc)
    assert tier1._load(db, _FP_ID).occurrence_count is None

    for dedup in (True, False):
        for enrichment_on in (True, False):
            cfg = dataclasses.replace(stream, DEDUP_ENABLED=dedup, ENRICHMENT_ENABLED=enrichment_on)
            ev = tier1.evaluate_alert(
                db,
                _FP_ID,
                adapter=_FakeComplete(responses=[_false_positive(), _verifier()]),
                cfg=cfg,
            )
            assert ev is not None and ev.facts["occurrence_count"] is None, (dedup, enrichment_on)


@pytest.mark.db
def test_the_burst_count_is_never_computed_for_a_soar_alert(db, stream, monkeypatch) -> None:
    receive_and_run(db, stream, fp_candidate())

    def _burst(*args, **kwargs):
        raise AssertionError("burst_count ran for an alert whose count SOAR did not send")

    monkeypatch.setattr(tier1, "burst_count", _burst)
    cfg = dataclasses.replace(stream, DEDUP_ENABLED=False)

    ev = tier1.evaluate_alert(
        db, _FP_ID, adapter=_FakeComplete(responses=[_false_positive(), _verifier()]), cfg=cfg
    )

    assert ev is not None and ev.facts["occurrence_count"] is None


def _wazuh_alert(db, stream) -> str:
    """The Wazuh fixture of `test_pipeline.py`, through the same stream: no `enrichment` block."""
    path = Path(__file__).parent / "fixtures" / "indexer_sample_rule5503.json"
    doc = json.loads(path.read_text(encoding="utf-8"))["_source"]
    doc["id"] = "1789200000.300002"
    receive_and_run(db, stream, doc)
    return doc["id"]


@pytest.mark.db
def test_an_alert_without_the_block_keeps_the_count_it_had(db, stream, monkeypatch) -> None:
    """The control of part 4: a Wazuh alert is read as before — the row's count with grouping on,
    the burst count (here the one alert itself) with `DEDUP_ENABLED=false`."""
    alert_id = _wazuh_alert(db, stream)
    assert tier1._load(db, alert_id).occurrence_count == 1
    calls: list[str] = []
    real = tier1.burst_count
    monkeypatch.setattr(
        tier1,
        "burst_count",
        lambda conn, alert, cfg: (calls.append(alert), real(conn, alert, cfg))[1],
    )
    answers = [_false_positive(), _verifier()]

    off = tier1.evaluate_alert(
        db,
        alert_id,
        adapter=_FakeComplete(responses=answers),
        cfg=dataclasses.replace(stream, DEDUP_ENABLED=False),
    )
    on = tier1.evaluate_alert(
        db,
        alert_id,
        adapter=_FakeComplete(responses=copy.deepcopy(answers)),
        cfg=dataclasses.replace(stream, DEDUP_ENABLED=True),
    )

    assert off is not None and on is not None
    assert off.facts["occurrence_count"] == 1 and isinstance(off.facts["occurrence_count"], int)
    assert on.facts["occurrence_count"] == 1
    assert calls == [alert_id]  # once, for the switch-off run only
    assert "occurrence_count: 1" in off.built.prompt.user
    assert "không rõ" not in off.built.prompt.user


@pytest.mark.db
def test_the_prompts_of_a_soar_alert_say_unknown_and_pass_the_linter(db, stream) -> None:
    receive_and_run(db, stream, fp_candidate())

    ev = tier1.evaluate_alert(
        db, _FP_ID, adapter=_FakeComplete(responses=[_false_positive(), _verifier()]), cfg=stream
    )

    assert ev is not None and ev.outcome == "ok" and ev.violations == []
    assert "occurrence_count: không rõ" in ev.built.prompt.user
    assert ev.vbuilt is not None and "occurrence_count: không rõ" in ev.vbuilt.prompt.user
    assert ev.facts["asset_criticality"] == "medium"  # the context is the payload's
    assert (ev.facts["ioc_reputation"], ev.facts["identity_privileged"]) == ("clean", "false")
    assert ev.facts["severity"] == "medium" and ev.facts["category"] == "malware"


@pytest.mark.db
def test_a_false_positive_on_a_soar_alert_is_forced_to_needs_review(db, stream) -> None:
    """End to end, the fake model saying `false_positive` under `mal-1` on an alert whose every fact
    but the count satisfies that rule: the rule cannot hold on an unknown count, and the final
    verdict is `needs_review`."""
    receive_and_run(db, stream, fp_candidate())

    ev = tier1.evaluate_alert(
        db, _FP_ID, adapter=_FakeComplete(responses=[_false_positive(), _verifier()]), cfg=stream
    )

    assert ev is not None and ev.outcome == "ok"
    assert ev.proposed_verdict == "false_positive"
    assert ev.final_verdict == "needs_review"
    assert ev.gate_result["forced"] is True and ev.forced_by
    assert kb.rule_holds(kb.get_decision_table("malware"), "mal-1", ev.facts) is False


@pytest.mark.db
def test_step_4_is_what_forces_it_end_to_end(db, stream) -> None:
    receive_and_run(db, stream, fp_candidate())

    ev = tier1.evaluate_alert(
        db, _FP_ID, adapter=_FakeComplete(responses=[_false_positive(), _verifier()]), cfg=stream
    )

    assert ev is not None
    assert ev.forced_by == ("step4",)
    assert ev.gate_result["missing"] == ["playbook_rule"]
    assert ev.gate_result["hallucination_flag"] is False
    assert ev.gate_result["mismatched_fields"] == []


@pytest.mark.db
def test_the_same_alert_with_a_wazuh_shaped_id_is_forced_the_same(db, stream) -> None:
    """The id's shape changes nothing about the gate: the Wazuh form still runs end to end."""
    receive_and_run(db, stream, fp_candidate(_WAZUH_ID))

    ev = tier1.evaluate_alert(
        db, _WAZUH_ID, adapter=_FakeComplete(responses=[_false_positive(), _verifier()]), cfg=stream
    )

    assert ev is not None and ev.outcome == "ok"
    assert f"alert_id: {_WAZUH_ID}" in ev.built.prompt.user
    assert ev.facts["occurrence_count"] is None
    assert ev.forced_by == ("step4",) and ev.final_verdict == "needs_review"
    assert ev.gate_result["hallucination_flag"] is False


@pytest.mark.db
def test_the_real_gl_id_is_a_fact_of_both_prompts_and_the_run_reaches_the_end(db, stream) -> None:
    """DEC-209 item 1, end to end: the alert keeps the `gl-…` id SOAR gave it, ①'s prompts say it
    as a fact, the linter passes, the gate runs, and nothing raised on the way."""
    receive_and_run(db, stream, fp_candidate())

    ev = tier1.evaluate_alert(
        db, _FP_ID, adapter=_FakeComplete(responses=[_false_positive(), _verifier()]), cfg=stream
    )

    assert ev is not None and ev.outcome == "ok" and ev.violations == []
    assert _FP_ID.startswith("gl-")
    assert f"alert_id: {_FP_ID} · rule_id: 100140" in ev.built.prompt.user
    assert ev.state is not None and ev.verification is not None
    assert ev.final_verdict == "needs_review"


def _true_positive() -> dict:
    """① says `true_positive`, its basis the facts of `fp_candidate` (any integer for the count)."""
    answer = _false_positive()
    answer["suggested_action"] = "true_positive"
    answer["structured_basis"]["playbook_rule_applied"] = None
    return answer


@pytest.mark.db
def test_a_true_positive_on_a_soar_alert_is_not_downgraded_by_the_unknown_count(db, stream) -> None:
    """Before DEC-209 item 2 step 2 forced EVERY answer on such an alert, `escalate` (now
    `true_positive`, P14-T01) included, to
    `needs_review` as a hallucination. Now only the `false_positive` that needs a rule is held back.
    """
    receive_and_run(db, stream, fp_candidate())

    ev = tier1.evaluate_alert(
        db,
        _FP_ID,
        adapter=_FakeComplete(responses=[_true_positive(), _verifier("true_positive")]),
        cfg=stream,
    )

    assert ev is not None and ev.outcome == "ok"
    assert ev.final_verdict == "true_positive" and ev.forced_by == ()
    assert ev.gate_result["hallucination_flag"] is False


@pytest.mark.db
def test_a_known_count_the_model_gets_wrong_is_still_flagged_at_step_2(db, stream) -> None:
    """The control of the tests above, on an alert with no block (a known count of 1): `99` is a
    hallucination, as before, and `1` is not. (The other basis fields are `fp_candidate`'s, which
    this Wazuh alert does not have, so they mismatch both times: only the count is compared.)"""
    alert_id = _wazuh_alert(db, stream)

    def flagged(answered: int):
        ev = tier1.evaluate_alert(
            db,
            alert_id,
            adapter=_FakeComplete(responses=[_false_positive(occurrence=answered), _verifier()]),
            cfg=stream,
        )
        assert ev is not None and ev.outcome == "ok" and ev.facts["occurrence_count"] == 1
        return ev

    wrong, right = flagged(99), flagged(1)

    assert "occurrence_count" in wrong.gate_result["mismatched_fields"]
    assert "occurrence_count" not in right.gate_result["mismatched_fields"]
    assert wrong.gate_result["hallucination_flag"] is True


@pytest.mark.db
def test_the_job_writes_its_rows_with_a_null_count(db, stream, monkeypatch) -> None:
    """`run_triage_job` on a SOAR alert: nothing in what it writes assumes an integer."""
    receive_and_run(db, stream, fp_candidate())
    job = Job(job_id=1, job_type="triage", subject_id=_FP_ID, attempts=1)

    tier1.run_triage_job(db, job, adapter=_FakeComplete(responses=[_false_positive(), _verifier()]))

    runs = db.execute(
        "SELECT role, jsonb_typeof(gate_result->'facts'->'occurrence_count'), "
        "result->>'suggested_action' FROM llm_runs WHERE subject_id = %s ORDER BY role",
        (_FP_ID,),
    ).fetchall()
    assert ("proposer", "null", "needs_review") in runs
    status = db.execute(
        "SELECT triage_status FROM alerts WHERE alert_id = %s", (_FP_ID,)
    ).fetchone()
    assert status == ("ready",)  # ① produced a suggestion (its verdict is the llm_runs row's)
