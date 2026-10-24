"""P13-T02 / DEC-210, spec §7.6 — `rag.history`: what analysts decided before, without AI.

For a subject (an alert or a case) the history is the closed fields and counts of earlier decisions:
the first key level with data wins, from the exact recurrence of one SOAR case down to the same
category on the same host. Only head alerts (`duplicate_of IS NULL`) first seen within
`RAG_HISTORY_DAYS` count, and only those that carry a decision: closed by Tier 1, in an open case, or
in a concluded case. The subject, its cluster and its case are never counted (A5).

Every test builds its rows on the `db` fixture's transaction (`tests.rag_data`); the expected
distributions are written out. `render_history` is pure and is tested without a database.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest
from app.infra import config
from app.rag.history import (
    CONCLUSIONS,
    DEDUP_KEY_EXPRESSION,
    LEVELS,
    Exclusion,
    History,
    decision_history,
    render_history,
    self_exclusion,
)
from app.rag.subject import Subject

from tests import conftest
from tests.rag_data import add_alert, add_case, add_user, soar_payload

CFG = config.Config()  # RAG_HISTORY_DAYS = 90
KEY = "SC03|pfSense||79.79.78.202|20261017-04"
EARLIER_KEY = "SC03|pfSense||79.79.78.202|20261016-23"


def history_of(db, alert_id: str, cfg: config.Config = CFG) -> History:
    return decision_history(db, Subject("alert", alert_id), cfg)


def case_history_of(db, case_id: str, cfg: config.Config = CFG) -> History:
    return decision_history(db, Subject("case", case_id), cfg)


# ── the levels ────────────────────────────────────────────────────────────────────────────────


def test_the_levels_are_six_and_named() -> None:
    assert LEVELS == (
        (0, "soar_case"),
        (1, "cluster"),
        (2, "scenario_host"),
        (3, "rule_host"),
        (4, "rule_source"),
        (5, "category_host"),
    )


@pytest.mark.db
def test_level_0_is_the_dedup_key_without_its_hour_bucket(db) -> None:
    add_alert(db, "s", raw_payload=soar_payload(dedup_key=KEY))
    add_alert(
        db,
        "p1",
        rule_id="777",
        agent_name="other-host",
        srcip="1.1.1.1",
        category="malware",
        status="closed_fp",
        days_ago=2,
        raw_payload=soar_payload(dedup_key=EARLIER_KEY),
    )
    h = history_of(db, "s")
    assert (h.level, h.key_name, h.total) == (0, "soar_case", 1)
    assert h.by_conclusion == {"tier1_closed_fp": 1}
    assert h.examples == ("p1",)


@pytest.mark.db
def test_level_0_matches_the_whole_base_and_nothing_longer_or_shorter(db) -> None:
    add_alert(db, "s", raw_payload=soar_payload(dedup_key=KEY))
    same = {
        "same-other-hour": "SC03|pfSense||79.79.78.202|20260101-00",
        "same-same-hour": KEY,
        "no-hour-bucket": "SC03|pfSense||79.79.78.202",  # no suffix: its base is itself
    }
    different = {
        "longer-base": "SC03|pfSense||79.79.78.202|extra|20261016-23",
        "other-address": "SC03|pfSense||79.79.78.203|20261016-23",
        "shorter-base": "SC03|pfSense||79.79.78|20261016-23",
        "other-scenario": "SC04|pfSense||79.79.78.202|20261016-23",
        "bucket-not-last": "SC03|pfSense||79.79.78.202|20261016-23|x",
    }
    for position, (name, key) in enumerate({**same, **different}.items()):
        add_alert(
            db,
            name,
            status="closed_fp",
            rule_id=f"r{position}",
            agent_name=f"h{position}",
            category=f"c{position}",
            days_ago=3,
            raw_payload=soar_payload(dedup_key=key),
        )
    h = history_of(db, "s")
    assert h.level == 0
    assert sorted(h.examples) == sorted(same)
    assert h.total == len(same)


@pytest.mark.db
def test_level_0_treats_like_wildcards_and_backslashes_in_a_key_as_text(db) -> None:
    key = "CORP\\host|SC_3|h%|"
    add_alert(db, "s", raw_payload=soar_payload(dedup_key=key + "20261017-04"))
    add_alert(
        db,
        "wild",
        status="closed_fp",
        rule_id="r1",
        agent_name="h1",
        category="c1",
        raw_payload=soar_payload(dedup_key="CORPXhost|SCX3|hYY|20261016-23"),
    )
    add_alert(
        db,
        "exact",
        status="closed_fp",
        rule_id="r2",
        agent_name="h2",
        category="c2",
        raw_payload=soar_payload(dedup_key=key + "20261016-23"),
    )
    h = history_of(db, "s")
    assert (h.level, h.examples) == (0, ("exact",))


@pytest.mark.db
def test_a_key_with_no_hour_bucket_matches_the_same_key(db) -> None:
    add_alert(db, "s", raw_payload=soar_payload(dedup_key="plain-key"))
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="r1",
        agent_name="h1",
        category="c1",
        raw_payload=soar_payload(dedup_key="plain-key"),
    )
    assert history_of(db, "s").level == 0


@pytest.mark.db
def test_level_0_is_skipped_without_soar_data(db) -> None:
    # two Wazuh alerts, nothing of SOAR in either: no key to match, and NULL is never equal to NULL
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1", dstip="2.2.2.2")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="1.1.1.1",
        dstip="2.2.2.2",
    )
    h = history_of(db, "s")
    assert h.level == 1  # the cluster key, not the SOAR case
    assert h.key_name == "cluster"


@pytest.mark.db
def test_level_0_is_skipped_when_only_the_earlier_alerts_have_a_key(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="2.2.2.2",
        raw_payload=soar_payload(dedup_key=EARLIER_KEY),
    )
    assert history_of(db, "s").level == 3


@pytest.mark.db
def test_level_1_is_the_cluster_key_rule_source_destination_host(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1", dstip="2.2.2.2")
    add_alert(
        db,
        "p1",
        status="closed_benign",
        rule_id="5710",
        agent_name="h1",
        srcip="1.1.1.1",
        dstip="2.2.2.2",
        category="recon",
        alert_user="someone",
    )
    h = history_of(db, "s")
    assert (h.level, h.key_name, h.total) == (1, "cluster", 1)
    assert h.by_conclusion == {"tier1_closed_benign": 1}


@pytest.mark.db
@pytest.mark.parametrize(
    "different", [{"rule_id": "9"}, {"srcip": "3.3.3.3"}, {"dstip": "4.4.4.4"}, {"agent_name": "x"}]
)
def test_one_column_of_the_cluster_key_off_is_not_level_1(db, different) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1", dstip="2.2.2.2")
    columns = {"rule_id": "5710", "agent_name": "h1", "srcip": "1.1.1.1", "dstip": "2.2.2.2"}
    add_alert(db, "p", status="closed_fp", category="recon", **{**columns, **different})
    assert history_of(db, "s").level != 1


@pytest.mark.db
def test_level_2_is_the_soar_scenario_and_the_host(db) -> None:
    add_alert(
        db,
        "s",
        rule_id="100190",
        agent_name="pfSense",
        srcip="1.1.1.1",
        raw_payload=soar_payload(scenario="SC03"),
    )
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="200000",
        agent_name="pfSense",
        srcip="2.2.2.2",
        category="recon",
        raw_payload=soar_payload(scenario="SC03"),
    )
    h = history_of(db, "s")
    assert (h.level, h.key_name, h.total) == (2, "scenario_host", 1)


@pytest.mark.db
def test_level_2_is_skipped_when_the_subject_has_no_scenario(db) -> None:
    # neither has a scenario: "no scenario" must not read as "the same scenario"
    add_alert(db, "s", rule_id="1", agent_name="pfSense", category="recon")
    add_alert(db, "p", status="closed_fp", rule_id="2", agent_name="pfSense", category="malware")
    h = history_of(db, "s")
    assert (h.level, h.total) == (None, 0)


@pytest.mark.db
def test_level_3_is_the_rule_and_the_host(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1", dstip="9.9.9.9")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="2.2.2.2",
        dstip="8.8.8.8",
        alert_user="u2",
        category="recon",
    )
    h = history_of(db, "s")
    assert (h.level, h.key_name, h.total) == (3, "rule_host", 1)


@pytest.mark.db
def test_level_4_is_the_rule_and_the_same_source_address(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h2",
        srcip="1.1.1.1",
        dstip="5.5.5.5",
        category="recon",
    )
    h = history_of(db, "s")
    assert (h.level, h.key_name, h.total) == (4, "rule_source", 1)


@pytest.mark.db
def test_level_4_is_also_the_rule_and_the_same_user(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", alert_user="hr01")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h2",
        alert_user="hr01",
        category="recon",
    )
    assert history_of(db, "s").level == 4


@pytest.mark.db
def test_level_4_counts_each_alert_once_when_both_source_and_user_match(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1", alert_user="hr01")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h2",
        srcip="1.1.1.1",
        alert_user="hr01",
        category="recon",
    )
    h = history_of(db, "s")
    assert (h.level, h.total) == (4, 1)


@pytest.mark.db
def test_an_empty_source_and_no_user_never_match_each_other(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="", category="recon")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h2",
        srcip="",
        category="malware",
    )
    h = history_of(db, "s")
    assert (h.level, h.total) == (None, 0)


@pytest.mark.db
def test_level_5_is_the_category_and_the_host(db) -> None:
    add_alert(db, "s", rule_id="111", agent_name="h1", category="recon", srcip="1.1.1.1")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="222",
        agent_name="h1",
        category="recon",
        srcip="2.2.2.2",
    )
    h = history_of(db, "s")
    assert (h.level, h.key_name, h.total) == (5, "category_host", 1)


@pytest.mark.db
def test_level_5_is_skipped_for_an_unresolved_alert(db) -> None:
    """`unknown` is no information: other unresolved alerts on the same host say nothing."""
    add_alert(db, "s", rule_id="111", agent_name="h1", category="unknown", srcip="1.1.1.1")
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="222",
        agent_name="h1",
        category="unknown",
        srcip="2.2.2.2",
    )
    h = history_of(db, "s")
    assert (h.level, h.total) == (None, 0)


@pytest.mark.db
def test_an_unresolved_alert_still_gets_the_levels_that_do_not_read_the_category(db) -> None:
    add_alert(db, "s", rule_id="111", agent_name="h1", category="unknown", srcip="1.1.1.1")
    add_alert(
        db,
        "same-rule",
        status="closed_benign",
        rule_id="111",
        agent_name="h1",
        category="unknown",
        srcip="2.2.2.2",
    )
    h = history_of(db, "s")
    assert (h.level, h.key_name, h.total) == (3, "rule_host", 1)


@pytest.mark.db
def test_a_case_skips_level_5_for_its_unresolved_heads_and_keeps_the_others(db) -> None:
    user = add_user(db)
    add_alert(db, "h0", rule_id="111", agent_name="hostA", category="unknown", srcip="1.1.1.1")
    add_alert(db, "h1", rule_id="112", agent_name="hostB", category="recon", srcip="1.1.1.2")
    case = add_case(db, user, ["h0", "h1"])
    add_alert(
        db,
        "p-unknown",
        status="closed_fp",
        rule_id="900",
        agent_name="hostA",
        category="unknown",
        srcip="2.2.2.2",
    )
    add_alert(
        db,
        "p-recon",
        status="closed_benign",
        rule_id="901",
        agent_name="hostB",
        category="recon",
        srcip="2.2.2.3",
    )
    h = case_history_of(db, case)
    assert (h.level, h.key_name, h.total) == (5, "category_host", 1)
    assert h.examples == ("p-recon",)


@pytest.mark.db
def test_the_first_level_with_data_wins_and_counts_only_its_own_alerts(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1", dstip="2.2.2.2")
    add_alert(  # level 1 and every level below
        db,
        "exact",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="1.1.1.1",
        dstip="2.2.2.2",
    )
    add_alert(  # only from level 3 down
        db,
        "looser",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="7.7.7.7",
        dstip="8.8.8.8",
    )
    h = history_of(db, "s")
    assert (h.level, h.total, h.examples) == (1, 1, ("exact",))


@pytest.mark.db
def test_a_level_whose_alerts_carry_no_decision_is_passed_over(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1", dstip="2.2.2.2")
    add_alert(  # the exact cluster, but nobody decided it
        db,
        "open-one",
        status="queued_tier1",
        rule_id="5710",
        agent_name="h1",
        srcip="1.1.1.1",
        dstip="2.2.2.2",
    )
    add_alert(
        db,
        "decided",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="7.7.7.7",
        dstip="8.8.8.8",
    )
    h = history_of(db, "s")
    assert (h.level, h.examples) == (3, ("decided",))


# ── what is counted, and how ──────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_the_distribution_of_decisions(db) -> None:
    user = add_user(db)
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")

    def prior(alert_id: str, days_ago: float, **columns) -> str:
        columns.setdefault("category", "recon")
        return add_alert(
            db,
            alert_id,
            rule_id="5710",
            agent_name="h1",
            srcip=f"10.9.{len(alert_id)}.{days_ago:.0f}",
            days_ago=days_ago,
            **columns,
        )

    prior("f1", 5, status="closed_fp")
    prior("f2", 4, status="closed_fp")
    prior("b1", 3, status="closed_benign")
    prior("esc", 2, status="escalated_tier2")
    prior("cfp", 6, status="closed_fp")
    prior("cpv", 7, status="closed_benign")
    prior("cin", 8, status="closed_confirmed")
    add_case(db, user, ["esc"], status="investigating")
    add_case(db, user, ["cfp"], status="concluded_fp")
    add_case(db, user, ["cpv"], status="concluded_policy_violation")
    add_case(db, user, ["cin"], status="confirmed_incident")
    # carry no decision, or are not heads
    prior("queued", 1, status="queued_tier1")
    prior("auto", 1, status="auto_closed")
    prior("dup", 1, status="duplicate", duplicate_of="f1")
    # the newest sighting among the counted ones is the open case's alert
    db.execute(
        "UPDATE alerts SET last_seen_at = now() - interval '12 hours' WHERE alert_id = 'esc'"
    )
    (expected_last_seen,) = db.execute("SELECT now() - interval '12 hours'").fetchone()

    h = history_of(db, "s")

    assert h.level == 3
    assert h.total == 7
    assert h.by_conclusion == {
        "tier1_closed_fp": 2,
        "tier1_closed_benign": 1,
        "escalated_open": 1,
        "concluded_fp": 1,
        "concluded_policy_violation": 1,
        "confirmed_incident": 1,
    }
    assert h.last_seen == expected_last_seen
    assert h.examples == ("esc", "b1", "f2")  # the three newest first sightings, newest first


@pytest.mark.db
def test_a_conclusion_that_did_not_happen_is_not_a_key(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(db, "p", status="closed_fp", rule_id="5710", agent_name="h1", srcip="2.2.2.2")
    assert history_of(db, "s").by_conclusion == {"tier1_closed_fp": 1}


def test_the_conclusions_are_the_six_this_module_names() -> None:
    assert CONCLUSIONS == (
        "tier1_closed_fp",
        "tier1_closed_benign",
        "escalated_open",
        "concluded_fp",
        "concluded_policy_violation",
        "confirmed_incident",
    )


@pytest.mark.db
def test_only_head_alerts_are_counted(db) -> None:
    user = add_user(db)
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(db, "head", status="closed_fp", rule_id="5710", agent_name="h1", srcip="2.2.2.2")
    # a decision closes the head's duplicates with it (A16): they carry the same status, and one
    # sits in a concluded case. Neither is a decision of its own.
    for position in range(3):
        add_alert(
            db,
            f"dup{position}",
            status="closed_fp",
            duplicate_of="head",
            rule_id="5710",
            agent_name="h1",
            srcip="2.2.2.2",
        )
    add_alert(
        db,
        "dup-in-case",
        status="closed_fp",
        duplicate_of="head",
        rule_id="5710",
        agent_name="h1",
        srcip="2.2.2.2",
    )
    add_case(db, user, [], status="concluded_fp", duplicates=["dup-in-case"])
    h = history_of(db, "s")
    assert (h.total, h.examples) == (1, ("head",))
    assert h.by_conclusion == {"tier1_closed_fp": 1}


@pytest.mark.db
def test_an_escalated_alert_with_no_case_carries_no_decision(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(db, "p", status="escalated_tier2", rule_id="5710", agent_name="h1", srcip="2.2.2.2")
    assert history_of(db, "s").total == 0  # escalated, but in no case: nothing to count


@pytest.mark.db
def test_examples_are_at_most_three_and_ties_go_by_id(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    for name in ("d", "b", "e", "a", "c"):
        add_alert(
            db,
            name,
            status="closed_fp",
            rule_id="5710",
            agent_name="h1",
            srcip=f"9.9.9.{ord(name)}",
            days_ago=2,
        )
    h = history_of(db, "s")
    assert h.total == 5
    assert h.examples == ("a", "b", "c")


# ── the window ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_only_alerts_first_seen_within_the_window_count(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(
        db,
        "inside",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="2.2.2.2",
        days_ago=89,
    )
    add_alert(
        db,
        "outside",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="3.3.3.3",
        days_ago=91,
    )
    h = history_of(db, "s")
    assert (h.total, h.examples) == (1, ("inside",))


@pytest.mark.db
def test_the_window_is_the_key_rag_history_days(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(
        db,
        "p89",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="2.2.2.2",
        days_ago=89,
    )
    add_alert(
        db,
        "p10",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="3.3.3.3",
        days_ago=10,
    )
    short = dataclasses.replace(CFG, RAG_HISTORY_DAYS=30)
    long = dataclasses.replace(CFG, RAG_HISTORY_DAYS=365)
    assert history_of(db, "s", short).examples == ("p10",)
    assert history_of(db, "s", long).total == 2
    assert history_of(db, "s", dataclasses.replace(CFG, RAG_HISTORY_DAYS=1)).total == 0


@pytest.mark.db
def test_zero_days_is_an_empty_history(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    # first seen at the instant the transaction began: inside any window but an absent one
    add_alert(
        db,
        "p",
        status="closed_fp",
        rule_id="5710",
        agent_name="h1",
        srcip="2.2.2.2",
        days_ago=0,
    )
    assert history_of(db, "s").total == 1
    h = history_of(db, "s", dataclasses.replace(CFG, RAG_HISTORY_DAYS=0))
    assert h == History(None, None, 0, {}, None, ())


# ── the empty history ─────────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_nothing_before_is_total_0_and_no_level(db) -> None:
    add_alert(db, "s", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    h = history_of(db, "s")
    assert h == History(
        level=None, key_name=None, total=0, by_conclusion={}, last_seen=None, examples=()
    )


@pytest.mark.db
def test_a_subject_that_is_not_there_has_an_empty_history(db) -> None:
    assert history_of(db, "no-such-alert").total == 0
    assert case_history_of(db, "3f2b8c1e-5d4a-4e7b-9a60-1c2d3e4f5a6b").level is None


# ── self-exclusion (A5) ───────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_the_subject_is_not_in_its_own_history(db) -> None:
    add_alert(db, "s", status="closed_fp", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    h = history_of(db, "s")
    assert (h.level, h.total) == (None, 0)


@pytest.mark.db
def test_the_subjects_cluster_is_not_in_its_history(db) -> None:
    # the subject is a duplicate; its head and the head's other duplicates are the same event
    add_alert(db, "head", status="closed_fp", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    for name in ("dup1", "dup2"):
        add_alert(
            db,
            name,
            status="duplicate",
            duplicate_of="head",
            rule_id="5710",
            agent_name="h1",
            srcip="1.1.1.1",
        )
    add_alert(db, "other", status="closed_fp", rule_id="5710", agent_name="h1", srcip="2.2.2.2")
    h = history_of(db, "dup1")
    assert (h.total, h.examples) == (1, ("other",))
    # and the head, as the subject, does not count itself either
    assert history_of(db, "head").examples == ("other",)


@pytest.mark.db
def test_the_subjects_case_and_its_alerts_are_not_in_its_history(db) -> None:
    user = add_user(db)
    add_alert(db, "trigger", rule_id="5710", agent_name="h1", srcip="1.1.1.1")
    add_alert(db, "sibling", rule_id="5710", agent_name="h1", srcip="1.1.1.2")
    add_alert(
        db,
        "sibling-dup",
        status="duplicate",
        duplicate_of="sibling",
        rule_id="5710",
        agent_name="h1",
        srcip="1.1.1.2",
    )
    add_case(db, user, ["trigger", "sibling"], duplicates=["sibling-dup"])
    # another case, concluded, same rule and host: this one is history
    add_alert(db, "elsewhere", rule_id="5710", agent_name="h1", srcip="2.2.2.2")
    add_case(db, user, ["elsewhere"], status="concluded_fp")

    from_alert = history_of(db, "trigger")
    assert from_alert.examples == ("elsewhere",)
    assert from_alert.by_conclusion == {"concluded_fp": 1}


@pytest.mark.db
def test_a_case_subject_excludes_the_case_and_reads_the_keys_of_every_head(db) -> None:
    user = add_user(db)
    add_alert(db, "h0", rule_id="5710", agent_name="hostA", srcip="1.1.1.1")
    add_alert(db, "h1", rule_id="6000", agent_name="hostB", srcip="1.1.1.2")
    case = add_case(db, user, ["h0", "h1"])
    add_alert(db, "p-a", status="closed_fp", rule_id="5710", agent_name="hostA", srcip="2.2.2.2")
    add_alert(
        db, "p-b", status="closed_benign", rule_id="6000", agent_name="hostB", srcip="3.3.3.3"
    )
    add_alert(db, "p-none", status="closed_fp", rule_id="1", agent_name="hostC", srcip="4.4.4.4")

    h = case_history_of(db, case)

    assert (h.level, h.key_name, h.total) == (3, "rule_host", 2)
    assert h.by_conclusion == {"tier1_closed_fp": 1, "tier1_closed_benign": 1}
    assert sorted(h.examples) == ["p-a", "p-b"]


@pytest.mark.db
def test_a_case_subject_does_not_count_its_own_heads(db) -> None:
    user = add_user(db)
    add_alert(db, "h0", rule_id="5710", agent_name="hostA", srcip="1.1.1.1")
    case = add_case(db, user, ["h0"], status="concluded_fp")
    h = case_history_of(db, case)
    assert (h.level, h.total) == (None, 0)


# ── self_exclusion itself ─────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_the_exclusion_of_a_plain_alert_is_its_cluster(db) -> None:
    add_alert(db, "head", rule_id="5710", agent_name="h1")
    add_alert(db, "d1", status="duplicate", duplicate_of="head", agent_name="h1")
    add_alert(db, "d2", status="duplicate", duplicate_of="head", agent_name="h1")
    add_alert(db, "stranger", agent_name="h1")
    assert self_exclusion(db, Subject("alert", "head")) == Exclusion(
        frozenset({"head", "d1", "d2"}), frozenset()
    )


@pytest.mark.db
def test_the_exclusion_of_a_duplicate_is_its_head_and_the_heads_duplicates(db) -> None:
    add_alert(db, "head", rule_id="5710", agent_name="h1")
    add_alert(db, "d1", status="duplicate", duplicate_of="head", agent_name="h1")
    add_alert(db, "d2", status="duplicate", duplicate_of="head", agent_name="h1")
    assert self_exclusion(db, Subject("alert", "d1")).alert_ids == {"head", "d1", "d2"}


@pytest.mark.db
def test_the_exclusion_of_an_alert_in_a_case_adds_the_case_and_all_its_alerts(db) -> None:
    user = add_user(db)
    add_alert(db, "h0")
    add_alert(db, "h1")
    add_alert(db, "d0", status="duplicate", duplicate_of="h0")
    add_alert(db, "stranger")
    case = add_case(db, user, ["h0", "h1"], duplicates=["d0"])
    got = self_exclusion(db, Subject("alert", "h0"))
    assert got == Exclusion(frozenset({"h0", "h1", "d0"}), frozenset({case}))


@pytest.mark.db
def test_a_duplicate_of_a_case_head_is_excluded_though_it_carries_no_case_id(db) -> None:
    user = add_user(db)
    add_alert(db, "h0")
    add_alert(db, "late-dup", status="duplicate", duplicate_of="h0")
    case = add_case(db, user, ["h0"])  # `late-dup` is not marked with the case
    assert self_exclusion(db, Subject("case", case)).alert_ids == {"h0", "late-dup"}


@pytest.mark.db
def test_a_head_known_only_to_case_alerts_is_excluded(db) -> None:
    user = add_user(db)
    add_alert(db, "h0")
    add_alert(db, "h1")
    case = add_case(db, user, ["h0"])
    db.execute(
        "INSERT INTO case_alerts (case_id, alert_id, added_by) VALUES (%s, 'h1', %s)", (case, user)
    )  # `alerts.case_id` of h1 stays NULL
    assert self_exclusion(db, Subject("case", case)).alert_ids == {"h0", "h1"}


@pytest.mark.db
def test_a_duplicate_whose_head_is_in_a_case_excludes_that_case_too(db) -> None:
    user = add_user(db)
    add_alert(db, "h0")
    add_alert(db, "d0", status="duplicate", duplicate_of="h0")  # no case_id of its own
    case = add_case(db, user, ["h0"])
    assert self_exclusion(db, Subject("alert", "d0")) == Exclusion(
        frozenset({"h0", "d0"}), frozenset({case})
    )


@pytest.mark.db
def test_the_exclusion_of_a_case_is_the_case_and_its_alerts(db) -> None:
    user = add_user(db)
    add_alert(db, "h0")
    add_alert(db, "d0", status="duplicate", duplicate_of="h0")
    add_alert(db, "stranger")
    case = add_case(db, user, ["h0"], duplicates=["d0"])
    assert self_exclusion(db, Subject("case", case)) == Exclusion(
        frozenset({"h0", "d0"}), frozenset({case})
    )


@pytest.mark.db
def test_the_exclusion_of_a_subject_that_is_not_there_is_just_itself(db) -> None:
    other = "3f2b8c1e-5d4a-4e7b-9a60-1c2d3e4f5a6b"
    assert self_exclusion(db, Subject("alert", "ghost")) == Exclusion(
        frozenset({"ghost"}), frozenset()
    )
    assert self_exclusion(db, Subject("case", other)) == Exclusion(frozenset(), frozenset({other}))


def test_an_exclusion_is_frozen_sets() -> None:
    got = Exclusion(frozenset({"a"}), frozenset())
    with pytest.raises(dataclasses.FrozenInstanceError):
        got.alert_ids = frozenset()  # type: ignore[misc]


# ── the index expression ──────────────────────────────────────────────────────────────────────


def test_the_history_query_writes_the_expression_the_index_is_built_on() -> None:
    """`ix_alerts_soar_dedup_key` helps only a query that writes its expression as it was
    written in the migration (T01)."""
    migration = (conftest.REPO_ROOT / "docs" / "Schema" / "020_learned_knowledge.sql").read_text(
        encoding="utf-8"
    )
    (indexed,) = re.findall(r"CREATE INDEX ix_alerts_soar_dedup_key ON alerts \((.+)\);", migration)
    assert DEDUP_KEY_EXPRESSION.replace("a.raw_payload", "raw_payload") == indexed


# ── render_history ────────────────────────────────────────────────────────────────────────────


def test_render_history_is_one_key_value_line_per_field() -> None:
    h = History(
        level=3,
        key_name="rule_host",
        total=7,
        by_conclusion={
            "confirmed_incident": 1,
            "tier1_closed_fp": 2,
            "concluded_fp": 1,
            "escalated_open": 1,
            "tier1_closed_benign": 1,
            "concluded_policy_violation": 1,
        },
        last_seen=datetime(2026, 10, 16, 18, 13, 31, 570000, tzinfo=UTC),
        examples=("gl-01M539BAX06VRSYZQ35BR1XJ1D-46b75f26-c9a7-11f1-ae13-9a661b530912", "b", "c"),
    )
    assert render_history(h) == (
        "level: 3\n"
        "key_name: rule_host\n"
        "total: 7\n"
        "by_conclusion: tier1_closed_fp=2, tier1_closed_benign=1, escalated_open=1, "
        "concluded_fp=1, concluded_policy_violation=1, confirmed_incident=1\n"
        "last_seen: 2026-10-16\n"
        "examples: gl-01M539BAX06VRSYZQ35BR1XJ1D-46b75f26-c9a7-11f1-ae13-9a661b530912, b, c"
    )


def test_render_history_of_an_empty_history_says_none_everywhere_but_the_total() -> None:
    assert render_history(History(None, None, 0, {}, None, ())) == (
        "level: none\n"
        "key_name: none\n"
        "total: 0\n"
        "by_conclusion: none\n"
        "last_seen: none\n"
        "examples: none"
    )


def test_render_history_writes_the_date_in_utc() -> None:
    # 06:30 on the 17th at +07:00 is 23:30 on the 16th UTC
    late = datetime(2026, 10, 17, 6, 30, tzinfo=timezone(timedelta(hours=7)))
    h = History(0, "soar_case", 1, {"concluded_fp": 1}, late, ("a",))
    assert "last_seen: 2026-10-16\n" in render_history(h) + "\n"


def test_render_history_cannot_be_made_to_break_a_line() -> None:
    h = History(0, "soar_case", 1, {"concluded_fp": 1}, None, ("a\nlevel: 9", "b c"))
    lines = render_history(h).split("\n")
    assert len(lines) == 6
    assert [line.split(":")[0] for line in lines] == [
        "level",
        "key_name",
        "total",
        "by_conclusion",
        "last_seen",
        "examples",
    ]


def test_an_unknown_conclusion_key_is_still_rendered_after_the_known_ones() -> None:
    h = History(0, "soar_case", 2, {"zzz_other": 1, "concluded_fp": 1}, None, ())
    assert "by_conclusion: concluded_fp=1, zzz_other=1\n" in render_history(h) + "\n"
