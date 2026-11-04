"""P13-T02 / DEC-210, spec §7.6 — `rag.candidates`: the database search that precedes the agent.

The ranking agent is shown at most 20 active entries. Which 20 is decided here, with no model:
entries whose closed fields overlap the fingerprint's (category, a MITRE id, the SOAR scenario), plus
the top full-text hits (`plainto_tsquery('simple', …)` on `fingerprint_tsv`) for the fingerprint's rule
ids and rule descriptions, merged without repeats, minus any entry drafted from the subject itself
(A5) and any retired entry. Entries on both lists come first; the rest alternate, so a flood of
same-category entries cannot push the full-text hits out of the cap.

Rows are built on the `db` fixture's transaction (`tests.rag_data`). A fingerprint here is written
by hand in the shape `rag.fingerprint` produces.
"""

from __future__ import annotations

import uuid

import pytest
from app.rag.candidates import by_ids, candidates
from app.rag.entries import Entry
from app.rag.fingerprint import Fingerprint
from app.rag.history import Exclusion, self_exclusion
from app.rag.subject import Subject

from tests.rag_data import add_alert, add_case, add_entry, add_user

pytestmark = pytest.mark.db

NONE = Exclusion(frozenset(), frozenset())
PORT_SCAN = "Port Scan: External Host Probing Many Ports (pfSense)"


def fp(
    category: str = "recon",
    mitre: tuple[str, ...] = ("T1046",),
    rules: tuple[str, ...] = ("100190",),
    scenario: str | None = "SC03",
    descriptions: tuple[str, ...] = (PORT_SCAN,),
    log: str = "Oct <N> filterlog[<N>]: <N>,<N>,block,<IP_NGOAI>",
) -> Fingerprint:
    lines = [f"category: {category}"]
    if mitre:
        lines.append("mitre: " + " ".join(mitre))
    if rules:
        lines.append("rules: " + " ".join(rules))
    if scenario:
        lines.append(f"scenario: {scenario}")
    lines.extend(f"rule: {d}" for d in descriptions)
    lines.append(f"log: {log}")
    return Fingerprint(category, mitre, rules, scenario, "pf", (), "\n".join(lines))


def about(category: str, rules: str = "", description: str = "", **extra) -> dict:
    """The `fingerprint` column of an entry, in the shape the fingerprint module writes."""
    lines = [f"category: {category}"]
    if rules:
        lines.append(f"rules: {rules}")
    if description:
        lines.append(f"rule: {description}")
    return {"category": category, "fingerprint": "\n".join(lines), **extra}


def ids(found: list[Entry]) -> list[str]:
    return [entry.entry_id for entry in found]


# ── the closed-field overlap ──────────────────────────────────────────────────────────────────


def test_an_entry_of_the_same_category_is_a_candidate(db) -> None:
    same = add_entry(db, **about("recon"))
    add_entry(db, **about("malware"))
    assert ids(candidates(db, fp(), NONE)) == [same]


def test_an_entry_sharing_a_mitre_id_is_a_candidate(db) -> None:
    shares = add_entry(db, mitre_ids=["T1595", "T1046"], **about("malware"))
    add_entry(db, mitre_ids=["T1595"], **about("malware"))
    assert ids(candidates(db, fp(category="x_other"), NONE)) == [shares]


def test_an_entry_of_the_same_scenario_is_a_candidate(db) -> None:
    same = add_entry(db, soar_scenario="SC03", **about("malware"))
    add_entry(db, soar_scenario="SC04", **about("malware"))
    assert ids(candidates(db, fp(category="x_other", mitre=()), NONE)) == [same]


def test_no_scenario_in_the_fingerprint_matches_no_entry_by_scenario(db) -> None:
    add_entry(db, soar_scenario=None, **about("malware"))
    add_entry(db, soar_scenario="SC03", **about("malware"))
    assert (
        candidates(
            db, fp(category="x_other", mitre=(), scenario=None, rules=(), descriptions=()), NONE
        )
        == []
    )


def test_no_mitre_id_in_the_fingerprint_matches_no_entry_by_mitre(db) -> None:
    add_entry(db, mitre_ids=[], **about("malware"))
    add_entry(db, mitre_ids=["T1046"], **about("malware"))
    assert (
        candidates(
            db, fp(category="x_other", mitre=(), scenario=None, rules=(), descriptions=()), NONE
        )
        == []
    )


def test_a_shared_category_of_unknown_is_not_an_overlap(db) -> None:
    add_entry(db, **about("unknown"))
    unresolved = fp(category="unknown", mitre=(), scenario=None, rules=(), descriptions=())
    assert candidates(db, unresolved, NONE) == []


def test_an_unknown_entry_is_still_a_candidate_by_mitre_scenario_or_text(db) -> None:
    by_mitre = add_entry(db, mitre_ids=["T1046"], **about("unknown"))
    by_scenario = add_entry(db, soar_scenario="SC03", **about("unknown"))
    by_text = add_entry(db, **about("unknown", rules="100190"))
    nothing_else = add_entry(db, **about("unknown"))
    found = ids(candidates(db, fp(category="unknown"), NONE))
    assert sorted(found) == sorted([by_mitre, by_scenario, by_text])
    assert nothing_else not in found


def test_an_entry_that_overlaps_in_nothing_is_not_a_candidate(db) -> None:
    add_entry(
        db,
        mitre_ids=["T9999"],
        soar_scenario="SC09",
        rule_ids=["777"],
        **about("web_attack", rules="777", description="Something else entirely"),
    )
    assert candidates(db, fp(), NONE) == []


def test_an_empty_store_has_no_candidate(db) -> None:
    assert candidates(db, fp(), NONE) == []


def test_a_candidate_is_the_whole_entry(db) -> None:
    user = add_user(db)
    entry_id = add_entry(
        db,
        conclusion="concluded_fp",
        mitre_ids=["T1046"],
        tags=["port_scan"],
        soar_scenario="SC03",
        rule_ids=["100190"],
        log_source="pf",
        content="# the published text\n",
        **about("recon", rules="100190"),
    )
    db.execute(
        "UPDATE knowledge_entries SET approved_by = %s WHERE entry_id = %s", (user, entry_id)
    )
    (found,) = candidates(db, fp(), NONE)
    assert isinstance(found, Entry)
    assert found.entry_id == entry_id and found.content == "# the published text\n"
    assert found.mitre_ids == ("T1046",) and found.approved_by == user


# ── the full-text hits ────────────────────────────────────────────────────────────────────────


def test_an_entry_about_the_same_rule_is_found_by_full_text_though_no_closed_field_overlaps(
    db,
) -> None:
    # category, MITRE and scenario all differ: the category map changed since it was written
    found_by_text = add_entry(
        db,
        mitre_ids=["T9999"],
        soar_scenario="SC09",
        **about("old_category", rules="100190", description=PORT_SCAN),
    )
    add_entry(db, **about("old_category", rules="555", description="Unrelated rule"))
    assert ids(candidates(db, fp(), NONE)) == [found_by_text]


def test_the_rule_id_alone_is_enough(db) -> None:
    by_id = add_entry(db, **about("old_category", rules="5710 100190"))
    assert ids(candidates(db, fp(descriptions=(), category="x"), NONE)) == [by_id]


def test_a_rule_description_alone_is_enough_and_is_matched_whole(db) -> None:
    whole = add_entry(db, **about("old_category", description=PORT_SCAN))
    add_entry(db, **about("old_category", description="Port Scan: nothing else of the phrase"))
    assert ids(candidates(db, fp(rules=(), category="x"), NONE)) == [whole]


def test_full_text_is_case_blind_and_ignores_punctuation(db) -> None:
    hit = add_entry(
        db,
        **about(
            "old_category", description="port scan -- external host, probing many ports; pfsense"
        ),
    )
    assert ids(candidates(db, fp(rules=(), category="x"), NONE)) == [hit]


def test_a_date_in_the_log_does_not_keep_an_entry_out(db) -> None:
    hit = add_entry(
        db,
        fingerprint=f"category: old_category\nrules: 100190\nrule: {PORT_SCAN}\nlog: Nov <N>",
        category="old_category",
    )
    assert ids(candidates(db, fp(log="Oct <N> other"), NONE)) == [hit]


def test_query_syntax_in_a_description_is_text_not_syntax(db) -> None:
    add_entry(db, **about("recon"))
    hostile = fp(
        category="x",
        mitre=(),
        scenario=None,
        rules=("1 & 2 | !3",),
        descriptions=("a & b | !c :* ( ) ' \" \\ <-> <2>", "!!!", "   "),
    )
    assert candidates(db, hostile, NONE) == []


def test_a_fingerprint_with_nothing_to_search_for_finds_only_by_closed_fields(db) -> None:
    add_entry(db, **about("recon"))
    bare = Fingerprint("recon", (), (), None, "", (), "")
    assert len(candidates(db, bare, NONE)) == 1
    other = Fingerprint("malware", (), (), None, "", (), "")
    assert candidates(db, other, NONE) == []


# ── merged, without repeats, in order ─────────────────────────────────────────────────────────


def test_overlap_and_full_text_hits_are_merged_without_a_repeat(db) -> None:
    both = add_entry(db, **about("recon", rules="100190", description=PORT_SCAN))
    # shares one more closed field than `both`, so by overlap alone it would come first
    overlap_only = add_entry(db, mitre_ids=["T1046"], **about("recon"))
    text_only = add_entry(db, **about("old_category", rules="100190"))
    add_entry(db, **about("malware"))
    found = ids(candidates(db, fp(), NONE))
    assert found == [both, overlap_only, text_only]  # on both lists first; then the others


def test_an_entry_matching_by_two_phrases_is_returned_once(db) -> None:
    entry = add_entry(db, **about("old_category", rules="100190", description=PORT_SCAN))
    assert ids(candidates(db, fp(), NONE)) == [entry]


def test_more_closed_fields_in_common_come_first(db) -> None:
    one = add_entry(db, approved_days_ago=1, **about("recon"))
    two = add_entry(db, approved_days_ago=1, mitre_ids=["T1046"], **about("recon"))
    three = add_entry(
        db, approved_days_ago=1, mitre_ids=["T1046"], soar_scenario="SC03", **about("recon")
    )
    assert ids(candidates(db, fp(), NONE)) == [three, two, one]


def test_the_order_is_stable_newest_approval_first_among_equals(db) -> None:
    older = add_entry(db, approved_days_ago=9, **about("recon"))
    newer = add_entry(db, approved_days_ago=2, **about("recon"))
    assert ids(candidates(db, fp(), NONE)) == [newer, older]
    assert ids(candidates(db, fp(), NONE)) == ids(candidates(db, fp(), NONE))


# ── the cap ───────────────────────────────────────────────────────────────────────────────────


def test_at_most_twenty_by_default(db) -> None:
    for _ in range(30):
        add_entry(db, **about("recon"))
    assert len(candidates(db, fp(), NONE)) == 20


def test_the_limit_is_a_parameter_and_zero_is_none(db) -> None:
    for _ in range(8):
        add_entry(db, **about("recon"))
    assert len(candidates(db, fp(), NONE, limit=5)) == 5
    assert len(candidates(db, fp(), NONE, limit=50)) == 8
    assert candidates(db, fp(), NONE, limit=0) == []
    assert candidates(db, fp(), NONE, limit=-3) == []


def test_a_flood_of_closed_field_hits_cannot_push_every_full_text_hit_out_of_the_cap(db) -> None:
    for _ in range(25):
        add_entry(db, **about("recon"))
    text_only = add_entry(db, **about("old_category", rules="100190"))
    found = ids(candidates(db, fp(), NONE))
    assert len(found) == 20
    assert text_only in found


def test_the_cap_holds_when_both_lists_are_long(db) -> None:
    for _ in range(15):
        add_entry(db, **about("recon"))
    for _ in range(15):
        add_entry(db, **about("old_category", rules="100190"))
    found = ids(candidates(db, fp(), NONE))
    assert len(found) == 20 and len(set(found)) == 20


# ── retired entries ───────────────────────────────────────────────────────────────────────────


def test_a_retired_entry_never_appears_by_overlap_or_by_text(db) -> None:
    add_entry(db, status="retired", **about("recon"))
    add_entry(db, status="retired", **about("old_category", rules="100190", description=PORT_SCAN))
    active = add_entry(db, **about("recon"))
    assert ids(candidates(db, fp(), NONE)) == [active]


def test_only_retired_entries_means_no_candidate(db) -> None:
    add_entry(db, status="retired", **about("recon", rules="100190", description=PORT_SCAN))
    assert candidates(db, fp(), NONE) == []


# ── self-exclusion (A5) ───────────────────────────────────────────────────────────────────────


def test_an_entry_drafted_from_the_subject_alert_is_excluded(db) -> None:
    add_alert(db, "subject-alert", status="closed_fp")
    drafted = add_entry(db, source_alert_ids=["subject-alert"], **about("recon"))
    other = add_entry(db, source_alert_ids=["someone-else"], **about("recon"))
    found = ids(candidates(db, fp(), self_exclusion(db, Subject("alert", "subject-alert"))))
    assert found == [other] and drafted not in found


def test_an_entry_drafted_from_the_subjects_case_is_excluded_for_the_case_and_for_its_alerts(
    db,
) -> None:
    user = add_user(db)
    add_alert(db, "head")
    case_id = add_case(db, user, ["head"])
    drafted = add_entry(db, source_case_ids=[case_id], **about("recon"))
    other = add_entry(db, source_case_ids=[str(uuid.uuid4())], **about("recon"))
    for subject in (Subject("case", case_id), Subject("alert", "head")):
        found = ids(candidates(db, fp(), self_exclusion(db, subject)))
        assert found == [other], subject
        assert drafted not in found


def test_an_entry_drafted_from_any_alert_of_the_subjects_cluster_is_excluded(db) -> None:
    add_alert(db, "head")
    add_alert(db, "dup", status="duplicate", duplicate_of="head")
    drafted = add_entry(db, source_alert_ids=["head"], **about("recon"))
    found = candidates(db, fp(), self_exclusion(db, Subject("alert", "dup")))
    assert drafted not in ids(found)


def test_an_entry_with_one_excluded_source_among_several_is_excluded(db) -> None:
    drafted = add_entry(db, source_alert_ids=["other", "subject"], **about("recon"))
    found = candidates(db, fp(), Exclusion(frozenset({"subject"}), frozenset()))
    assert drafted not in ids(found)


def test_the_exclusion_applies_to_the_full_text_hits_too(db) -> None:
    drafted = add_entry(
        db,
        source_alert_ids=["subject"],
        **about("old_category", rules="100190", description=PORT_SCAN),
    )
    assert candidates(db, fp(), Exclusion(frozenset({"subject"}), frozenset())) == []
    assert ids(candidates(db, fp(), NONE)) == [drafted]


def test_an_exclusion_that_names_a_case_id_that_is_not_a_uuid_is_ignored(db) -> None:
    entry = add_entry(db, **about("recon"))
    found = candidates(db, fp(), Exclusion(frozenset(), frozenset({"not-a-uuid"})))
    assert ids(found) == [entry]
    assert db.execute("SELECT 1").fetchone() == (1,)


# ── by_ids: the vector hits, read back from the main database (P14-T06, spec §5.1 and §5.3) ───


def test_by_ids_returns_the_whole_entries_in_the_order_asked(db) -> None:
    first, second, third = (add_entry(db, **about("recon")) for _ in range(3))
    found = by_ids(db, [third, first, second], NONE)
    assert ids(found) == [third, first, second]
    assert all(isinstance(entry, Entry) and entry.content for entry in found)


def test_by_ids_leaves_out_a_retired_entry(db) -> None:
    """A vector row can outlive its entry (the embed job deletes it only when it runs): a hit for a
    retired entry is ignored."""
    live = add_entry(db, **about("recon"))
    retired = add_entry(db, status="retired", **about("recon"))
    assert ids(by_ids(db, [retired, live], NONE)) == [live]


def test_by_ids_leaves_out_an_id_that_is_no_entry(db) -> None:
    live = add_entry(db, **about("recon"))
    assert ids(by_ids(db, [str(uuid.uuid4()), live], NONE)) == [live]


def test_by_ids_leaves_out_an_entry_drafted_from_the_subject(db) -> None:
    """A5, as for the database search: an entry drafted from the subject itself is not a candidate."""
    alert = "ra-self"
    add_alert(db, alert, rule_id="100190", category="recon")
    own = add_entry(db, source_alert_ids=[alert], **about("recon"))
    other = add_entry(db, **about("recon"))
    exclusion = self_exclusion(db, Subject("alert", alert))
    assert ids(by_ids(db, [own, other], exclusion)) == [other]


def test_by_ids_of_nothing_is_nothing_and_a_repeat_is_once(db) -> None:
    live = add_entry(db, **about("recon"))
    assert by_ids(db, [], NONE) == []
    assert ids(by_ids(db, [live, live], NONE)) == [live]


def test_by_ids_takes_an_id_in_any_spelling_and_gives_the_canonical_one(db) -> None:
    live = add_entry(db, **about("recon"))
    assert ids(by_ids(db, [live.upper()], NONE)) == [live]


def test_by_ids_ignores_what_is_not_a_uuid(db) -> None:
    live = add_entry(db, **about("recon"))
    assert ids(by_ids(db, ["not-a-uuid", "", live], NONE)) == [live]
