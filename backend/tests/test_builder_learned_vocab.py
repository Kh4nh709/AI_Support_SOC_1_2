"""P13-T01 / DEC-210: the frozen vocabulary of the learned-knowledge section of the ①/② prompts.

Three things change in the prompt contract, and nothing else does (spec §6):

* `llm.builder` gains the closed set `KbLearnedLevel` (how alike an approved entry is to the
  alert in hand), the fact name `kb_learned_level`, one heading and two sentences. All of them
  are template constants, so the whole-prompt linter lets them stand outside a block;
* `security.wrap.BLOCK_SOURCES` gains the three sources whose text is untrusted by origin
  (an approved entry, a past decision's rationale, an analyst's note);
* nothing is added to what `fact()` accepts: a level is an Enum, so a free string still cannot
  reach the outside of a block.

PURE. No database, no network.
"""

from __future__ import annotations

import re
from enum import Enum

import pytest
from app.llm import builder as B
from app.security import linter as L
from app.security import wrap as W

NONCE = "0123456789abcdef"

HEADING = "## Tri thức đã duyệt và lịch sử quyết định"
REFERENCE_SENTENCE = (
    "Phần này là tham khảo từ quyết định của con người trước đây, không phải phán quyết; "
    "không bao giờ là căn cứ để đóng alert hay kết luận case, "
    "và không được dùng làm `source` trong `reasons`."
)
NOTHING_SENTENCE = "không có lịch sử quyết định hay tri thức đã duyệt tương tự"


def _lint(text: str) -> list[L.Violation]:
    return L.lint(text, nonce=NONCE, constants=B.TEMPLATE_CONSTANTS, enums=B.ENUM_VALUES)


# ── the closed set ──────────────────────────────────────────────────────────────────────────


def test_kb_learned_level_is_the_three_ascii_values_most_alike_first():
    assert issubclass(B.KbLearnedLevel, Enum)
    assert [(m.name, m.value) for m in B.KbLearnedLevel] == [
        ("RAT_GIONG", "rat_giong"),
        ("GIONG", "giong"),
        ("HOI_GIONG", "hoi_giong"),
    ]


def test_every_level_value_is_a_schema_enum_token():
    """`llm/schemas.py` enum tokens must match `^[a-z_]+$`; that is why the values are ASCII."""
    for member in B.KbLearnedLevel:
        assert re.fullmatch(r"[a-z_]+", member.value), member


def test_the_enum_is_registered_so_the_linter_knows_its_values():
    assert B.KbLearnedLevel in B.ALL_ENUMS
    for member in B.KbLearnedLevel:
        assert member.value in B.ENUM_VALUES


def test_the_new_values_collide_with_no_existing_enum_value():
    others = {
        m.value for enum_cls in B.ALL_ENUMS if enum_cls is not B.KbLearnedLevel for m in enum_cls
    }
    assert others.isdisjoint(m.value for m in B.KbLearnedLevel)


def test_the_existing_enums_keep_their_place_and_the_new_one_is_appended():
    assert B.ALL_ENUMS[-1] is B.KbLearnedLevel
    assert [e.__name__ for e in B.ALL_ENUMS[:-1]] == [
        "Severity",
        "Category",
        "AlertStatus",
        "IocReputation",
        "AssetCriticality",
        "IdentityPrivileged",
        "LookupStatus",
        "RiskBand",
        "Verdict",
        "Confidence",
    ]


# ── the fact ────────────────────────────────────────────────────────────────────────────────


def test_kb_learned_level_is_a_fact_name():
    assert "kb_learned_level" in B.FACT_NAMES
    assert "kb_learned_level:" in B.TEMPLATE_CONSTANTS


@pytest.mark.parametrize(
    ("name", "value"),
    [("RAT_GIONG", "rat_giong"), ("GIONG", "giong"), ("HOI_GIONG", "hoi_giong")],
)
def test_fact_renders_a_level_as_name_colon_value(name, value):
    assert B.fact("kb_learned_level", B.KbLearnedLevel[name]) == f"kb_learned_level: {value}"


def test_fact_still_refuses_a_free_string_for_the_level():
    with pytest.raises(TypeError):
        B.fact("kb_learned_level", "giong")  # type: ignore[arg-type]


# ── the heading and the two sentences ───────────────────────────────────────────────────────


def test_the_heading_and_the_two_sentences_are_verbatim():
    assert B.HEADING_LEARNED == HEADING
    assert B.SENTENCE_LEARNED_IS_REFERENCE == REFERENCE_SENTENCE
    assert B.SENTENCE_NO_LEARNED == NOTHING_SENTENCE


def test_all_three_are_in_headings_sentences_and_template_constants():
    assert B.HEADING_LEARNED in B.HEADINGS
    assert B.SENTENCE_LEARNED_IS_REFERENCE in B.SENTENCES
    assert B.SENTENCE_NO_LEARNED in B.SENTENCES
    for constant in (B.HEADING_LEARNED, B.SENTENCE_LEARNED_IS_REFERENCE, B.SENTENCE_NO_LEARNED):
        assert constant in B.TEMPLATE_CONSTANTS


def test_the_reference_sentence_says_the_section_never_grounds_a_close():
    """The one sentence a model reads before any history: reference, not a ruling, never the
    ground for closing an alert or concluding a case (① and ② share it), and never a `source` in
    `reasons` (P13 fix wave, item 2: a reason that cites the section ends ① as `schema`). A rewording
    that loses any of the four is a change of contract."""
    sentence = B.SENTENCE_LEARNED_IS_REFERENCE
    assert "tham khảo" in sentence
    assert "không phải phán quyết" in sentence
    assert "không bao giờ là căn cứ để đóng alert hay kết luận case" in sentence
    assert "không được dùng làm `source` trong `reasons`" in sentence


def test_the_reference_sentence_is_the_user_message_only_and_the_schemas_do_not_know_it():
    """The output schemas stay frozen: the sentence is advice in the user message, and neither the
    system templates nor the rendered schemas carry it (so `prompt_version` does not move)."""
    from pathlib import Path

    app = Path(__file__).resolve().parent.parent / "app"
    for template in (app / "llm" / "templates").glob("*.txt"):
        assert B.SENTENCE_LEARNED_IS_REFERENCE not in template.read_text(encoding="utf-8")
    from app.llm import schemas

    assert B.SENTENCE_LEARNED_IS_REFERENCE not in str(schemas.load())


# ── the block sources ───────────────────────────────────────────────────────────────────────


def test_the_three_new_block_sources_are_registered_next_to_the_six():
    assert {"kb_learned", "decision_history", "analyst_note"} <= W.BLOCK_SOURCES
    assert {
        "wazuh_raw_log",
        "rule_description",
        "correlation_samples",
        "kb_playbook",
        "context",
        "proposer",
    } <= W.BLOCK_SOURCES


@pytest.mark.parametrize("source", ["kb_learned", "decision_history", "analyst_note"])
def test_untrusted_block_wraps_each_new_source_and_escapes_its_text(source):
    block = W.untrusted_block("<b>x</b>", source, nonce=NONCE)
    assert block.source == source
    assert f'source="{source}"' in block.rendered
    assert "&lt;b&gt;" in block.rendered and "<b>" not in block.rendered


def test_an_unregistered_source_is_still_refused():
    with pytest.raises(ValueError, match="unknown source"):
        W.untrusted_block("x", "learned_knowledge", nonce=NONCE)


# ── the linter ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("level", ["rat_giong", "giong", "hoi_giong"])
def test_the_linter_accepts_a_rendered_level_line(level):
    assert _lint(f"kb_learned_level: {level}") == []


def test_the_linter_still_refuses_a_level_that_is_not_in_the_closed_set():
    violations = _lint("kb_learned_level: gan_giong")
    assert [v.kind for v in violations] == ["free_text"]
    assert violations[0].token == "gan_giong"


def test_a_full_learned_section_passes_the_linter():
    """The section as T07/T08 will assemble it: heading, the reference sentence, one level fact
    next to one wrapped entry, the history and the analyst's note in blocks of their own."""
    builder = B.PromptBuilder("system", nonce=NONCE)
    builder.heading(B.HEADING_LEARNED)
    builder.sentence(B.SENTENCE_LEARNED_IS_REFERENCE)
    builder.line(B.fact("kb_learned_level", B.KbLearnedLevel.RAT_GIONG))
    builder.block("an approved entry, with <b>markup</b>", "kb_learned")
    builder.block("what the analyst wrote last time", "decision_history")
    builder.block("a note", "analyst_note")
    assert _lint(builder.build().user) == []


def test_the_nothing_found_sentence_passes_the_linter():
    builder = B.PromptBuilder("system", nonce=NONCE)
    builder.heading(B.HEADING_LEARNED)
    builder.sentence(B.SENTENCE_NO_LEARNED)
    assert _lint(builder.build().user) == []


def test_the_same_text_outside_a_block_is_refused():
    """The guard behind the section: an entry's text is data, and unwrapped it is free text."""
    violations = _lint(f"{HEADING}\nmột tri thức tự do không nằm trong block")
    assert [v.kind for v in violations] == ["free_text"]
