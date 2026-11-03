"""INT-T01, ruling 2 - the ① prompt with both features: P13's learned section (DEC-210) and S2's
`siem_context` block (DEC-211), built together by `build_proposer_prompt`.

The two branches never met until INT-T01, and each has its own byte-identity fixtures
(`test_triage_rag.GOLDEN_USER`, `test_siem_context`). Those stay green unchanged. What none of them can say is
what the prompt looks like with both features on, so this file pins that, and only that:

* each block keeps the place its own branch gave it: `siem_context` after `context` and before the
  correlation, the learned section after the playbook and before the request;
* each feature is independent of the other: take the learned section out of the combined message and it is
  what soar-followup built (RAG off); take the `siem_context` block out and it is what P13 built (flag off);
* the token budget cuts the learned section first (P13's order), and nothing of S2's goes before it: S2 has no
  cut of its own in the budget (its 8 KB cap is inside its block), so the block is whole whatever the budget;
* with both features off, the USER message is byte for byte main's (and P13's). The SYSTEM message is not:
  it carries DEC-211's `siem_context` in the `triage_v2` `reasons[].source` enum
  (`llm/templates/output_schemas.json`, context pack 6.2), whatever the flag says, because the enum is a
  contract and not a prompt option. That one value is the whole difference, and it adds 5 to the estimated
  tokens (13 bytes). The criterion of INT-T01 is therefore "user message identical, system message differs
  by that value" (F1 of the review, ruling a), not "the message main built".

PURE. No database, no socket.
"""

from __future__ import annotations

import hashlib
import re

import pytest
from app.llm import builder as B
from app.llm import triage as T
from app.security import linter

from tests.test_llm_triage import NONCE, _cfg, _correlation, _inp
from tests.test_siem_context import sc03_enrichment
from tests.test_triage_rag import (
    GOLDEN_WARNINGS,
    HISTORY_ONLY,
    OK,
    REQUEST,
    SECTION_OK,
)

PLAYBOOK_TEXT = "PLAYBOOK_TEXT_FIXED"
#: The one value S2 added to the `triage_v2` `reasons[].source` enum, and so to the ① system message.
SIEM_ENUM_VALUE = "|siem_context"
#: sha256 of the ① system message without S2's value: the integration's system message with
#: `SIEM_ENUM_VALUE` taken out once. 2531 bytes against the integration's 2544. It was main's
#: (ba31def; P13's, 923c6b2, is the same bytes: b3c884fd1d9a...) until P14-T01 (DEC-213) moved the system
#: message on purpose: the new opening, `false_positive | true_positive`, and `## Schema triage_v3`.
MAIN_SYSTEM_SHA256 = "80c7a9b8c0461c4aa7b3ea8f661a23daae3da50dfa437e541dc2d55855a862d6"
#: One whole `siem_context` block, with the blank line after it.
SIEM_BLOCK = re.compile(
    r'<untrusted_data nonce="\w+" source="siem_context">.*?</untrusted_data nonce="\w+">\n\n',
    re.DOTALL,
)


def build(
    *, learned=None, siem: bool = True, inp=None, correlation=None, **config_overrides
) -> T.BuiltTriagePrompt:
    inp = inp or _inp(siem_enrichment=sc03_enrichment(n_logs=60))
    return T.build_proposer_prompt(
        inp,
        T.build_facts(inp, correlation),
        correlation,
        PLAYBOOK_TEXT,
        None,
        cfg=_cfg(**config_overrides),
        nonce=NONCE,
        learned=learned,
        include_siem_context=siem,
    )


def lint(built: T.BuiltTriagePrompt) -> list:
    return linter.lint(
        built.prompt.user,
        nonce=built.prompt.nonce,
        constants=B.TEMPLATE_CONSTANTS,
        enums=B.ENUM_VALUES,
    )


def siem_text(built: T.BuiltTriagePrompt) -> str:
    return built.prompt.block_index["siem_context"].plain


def test_both_blocks_are_present_each_in_the_place_its_branch_gave_it() -> None:
    corr = _correlation()
    both = build(learned=OK, correlation=corr)

    assert list(both.prompt.block_index) == [
        "rule_description",
        "wazuh_raw_log",
        "context",
        "siem_context",  # S2: after the context, before the correlation
        "correlation_samples",
        "kb_playbook",
        "decision_history",  # P13: after the playbook, before the request
        "kb_learned",
    ]
    user = both.prompt.user
    assert (
        user.index('source="context"')
        < user.index('source="siem_context"')
        < user.index("## Tương quan")
        < user.index("## Playbook")
        < user.index(B.HEADING_LEARNED)
        < user.index('source="decision_history"')
        < user.index('source="kb_learned"')
        < user.index(B.SENTENCE_LEARNED_IS_REFERENCE)
        < user.index(B.HEADING_REQUEST)
    )
    assert both.learned_used is True
    assert both.warnings == GOLDEN_WARNINGS
    assert lint(both) == []


def test_each_feature_is_what_its_own_branch_built_when_the_other_is_off() -> None:
    corr = _correlation()
    both = build(learned=OK, correlation=corr)
    rag_off = build(learned=None, correlation=corr)  # soar-followup's message
    siem_off = build(learned=OK, siem=False, correlation=corr)  # P13's message

    # taking the learned section out of the combined message leaves soar-followup's, byte for byte
    assert both.prompt.user.replace(f"{SECTION_OK}\n\n", "") == rag_off.prompt.user
    assert SECTION_OK in both.prompt.user and SECTION_OK not in rag_off.prompt.user
    # taking the `siem_context` block out leaves P13's
    assert SIEM_BLOCK.sub("", both.prompt.user) == siem_off.prompt.user
    assert "siem_context" in both.prompt.block_index
    assert "siem_context" not in siem_off.prompt.block_index
    # and the block itself does not depend on the section
    assert siem_text(both) == siem_text(rag_off)
    assert both.prompt.system == rag_off.prompt.system == siem_off.prompt.system


def test_with_both_off_the_user_message_is_the_one_main_built() -> None:
    """`GOLDEN_USER` of `test_triage_rag` is main's USER message; the enrichment present and the flag off, or
    the enrichment absent, with no `learned`, is that message again. The system message is not main's (see
    the next test), so this is the claim and not "the message main built"."""
    from tests.test_triage_rag import GOLDEN_USER

    present_but_off = build(learned=None, siem=False, inp=_inp(siem_enrichment=sc03_enrichment()))
    absent = build(learned=None, inp=_inp())
    for built in (present_but_off, absent):
        assert built.prompt.user == GOLDEN_USER
        assert built.warnings == GOLDEN_WARNINGS
        assert built.learned_used is False


def test_the_system_message_differs_from_mains_by_exactly_the_siem_context_enum_value() -> None:
    """F1 of the INT-T01 review, ruling (a): the `triage_v3` schema in the system message lists the
    `reasons[].source` values, and S2 (DEC-211 item 4) added `siem_context` to it. Whatever the flag and
    whatever `learned` holds, the system message is the same text, and taking that one value out of it once
    gives the system message without S2, byte for byte (the hash was main's until P14-T01 moved the
    system message on purpose, see `MAIN_SYSTEM_SHA256`). It costs 5 estimated tokens."""
    from app.llm.adapter import estimate_tokens

    corr = _correlation()
    systems = {
        (flag, learned is not None): build(
            learned=learned, siem=flag, correlation=corr
        ).prompt.system
        for flag in (True, False)
        for learned in (None, OK)
    }
    system = systems[(True, False)]
    assert set(systems.values()) == {system}  # not the flag, not the learned section

    assert system.count(SIEM_ENUM_VALUE) == 1
    assert "|kb_playbook|context|siem_context\n" in system  # in the reasons[].source enum, last
    main_system = system.replace(SIEM_ENUM_VALUE, "", 1)
    assert hashlib.sha256(main_system.encode()).hexdigest() == MAIN_SYSTEM_SHA256
    assert len(system.encode()) - len(main_system.encode()) == len(SIEM_ENUM_VALUE) == 13
    assert estimate_tokens(system) - estimate_tokens(main_system) == 5


def test_the_budget_cuts_the_learned_section_first_and_never_the_siem_block_before_it() -> None:
    siem_only = build(learned=None)
    both = build(learned=OK)
    assert both.estimated_tokens > siem_only.estimated_tokens

    # one token short of the combined message: the entries go, and that is enough
    history_only = build(learned=HISTORY_ONLY)
    cut = build(learned=OK, PROMPT_TOTAL_BUDGET_TOKENS=history_only.estimated_tokens)
    assert cut.warnings == [*GOLDEN_WARNINGS, "learned_entries_dropped"]
    assert cut.prompt.user == history_only.prompt.user
    assert siem_text(cut) == siem_text(siem_only)

    # down to the message without the section: the history goes too, and the S2 block is exactly as it was
    exact = build(learned=OK, PROMPT_TOTAL_BUDGET_TOKENS=siem_only.estimated_tokens)
    assert exact.warnings == [
        *GOLDEN_WARNINGS,
        "learned_entries_dropped",
        "learned_history_dropped",
    ]
    assert exact.prompt.user == siem_only.prompt.user  # soar-followup's message, byte for byte
    assert exact.learned_used is False
    assert B.HEADING_LEARNED not in exact.prompt.user
    assert siem_text(exact) == siem_text(siem_only)
    assert "siem_context" in exact.prompt.block_index


def test_a_budget_the_learned_cuts_cannot_meet_goes_on_to_the_old_steps_and_the_siem_block_stays() -> (
    None
):
    big = _inp(siem_enrichment=sc03_enrichment(n_logs=60), raw_log="x" * 20_000)
    siem_only = build(learned=None, inp=big)
    not_enough = build(
        learned=OK, inp=big, PROMPT_TOTAL_BUDGET_TOKENS=siem_only.estimated_tokens - 1
    )

    assert not_enough.warnings[: len(GOLDEN_WARNINGS) + 2] == [
        *GOLDEN_WARNINGS,
        "learned_entries_dropped",
        "learned_history_dropped",
    ]
    assert not_enough.warnings[len(GOLDEN_WARNINGS) + 2] == "raw_log_cut_to_8192"
    # whatever the later steps do, none of them is S2's: the block is the one the flag-only build made
    assert siem_text(not_enough) == siem_text(siem_only)
    assert not any("siem" in warning for warning in not_enough.warnings)
    assert lint(not_enough) == []


def test_the_request_sentence_is_still_last_with_both_on() -> None:
    both = build(learned=OK)
    assert both.prompt.user.endswith(REQUEST)
    assert both.prompt.user.count(B.HEADING_LEARNED) == 1


@pytest.mark.parametrize("learned", [None, OK, HISTORY_ONLY])
def test_the_whole_prompt_with_both_passes_the_linter(learned) -> None:
    assert lint(build(learned=learned, correlation=_correlation())) == []
