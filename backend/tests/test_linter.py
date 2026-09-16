"""`security.linter` — every character outside an untrusted_data block is a template
constant, an enum, an integer, a datetime or an id (P3-T03, context pack G6').

Written fresh against the P3-T03 card and context pack §7.2/§7.4. The four
`legacy_*.txt` fixtures reproduce, as literal strings, the shapes the legacy builder
got wrong (its own dependency is not importable from a clean checkout — the card
names it, this file never imports it); `v3_valid.txt` is a full v3-shaped user
message hand-built from `app.llm.builder`'s own constants, so it cannot drift from
the builder silently (`test_fixture_constants_are_the_builders`).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.llm import builder as B
from app.security import linter as L

NONCE = "0123456789abcdef"
FIXTURES = Path(__file__).parent / "fixtures" / "linter"
TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "app" / "llm" / "templates"


def _read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text("utf-8")


def _lint(text: str, *, nonce: str = NONCE) -> list[L.Violation]:
    return L.lint(text, nonce=nonce, constants=B.TEMPLATE_CONSTANTS, enums=B.ENUM_VALUES)


def _sample_v3_message(nonce: str) -> str:
    """A representative ① user message in the §4.1 shape: headings, fact lines,
    all five block sources, two of the mandatory sentences. Built entirely from
    `app.llm.builder`'s own constants — no literal heading or sentence text."""
    pb = B.PromptBuilder(system="(system prompt not linted)", nonce=nonce)

    pb.heading(B.HEADING_ALERT)
    pb.line(B.fact("alert_id", B.Id("alert_id", "1786903016.121311")))
    pb.line(B.fact("rule_id", B.Id("rule_id", "40112")), B.fact("rule_level", 12))
    pb.line(B.fact("severity", B.Severity.CRITICAL), B.fact("category", B.Category.SSH_BRUTE_FORCE))
    pb.line(B.fact("occurrence_count", 3))
    pb.line(B.fact("alert_time", datetime(2026, 8, 16, 17, 56, 56, tzinfo=UTC)))
    pb.line(B.fact("mitre", B.Id("mitre", "T1110")))
    pb.line(B.fact("agent_id", B.Id("agent_id", "001")))

    pb.block(
        "Multiple authentication failures followed by a success.",
        "rule_description",
        alert_id=B.Id("alert_id", "1786903016.121311"),
    )

    pb.heading(B.HEADING_CONTEXT)
    pb.block(
        "hostname: user1-IA1803, role: workstation, owner: (unassigned)",
        "context",
        alert_id=B.Id("alert_id", "1786903016.121311"),
    )
    pb.sentence("ioc:", B.SENTENCE_ABSENT)

    pb.block(
        "Aug 16 17:56:55 user1-IA1803 sshd[136570]: Accepted password for user1 "
        "from 127.0.0.1 port 48104 ssh2",
        "wazuh_raw_log",
        alert_id=B.Id("alert_id", "1786903016.121311"),
    )

    pb.heading(B.HEADING_CORRELATION)
    pb.block(
        "5710 alerts, 12 clusters, same srcip, last seen 2026-08-16T17:50:00+00:00",
        "correlation_samples",
    )

    pb.heading(B.HEADING_PLAYBOOK)
    pb.block(
        "SSH brute force: check occurrence_count and asset_criticality before escalating.",
        "kb_playbook",
        category=B.Category.SSH_BRUTE_FORCE,
    )

    pb.heading(B.HEADING_REQUEST)
    pb.sentence(B.SENTENCE_REQUEST_TRIAGE)

    return pb.build().user


# ───────────────────────────────────────────────── the four legacy-violation fixtures
def test_legacy_description_outside_is_rejected():
    violations = _lint(_read_fixture("legacy_description_outside.txt"))
    print(f"legacy_description_outside.txt: {len(violations)} violation(s)")
    assert len(violations) == 1
    v = violations[0]
    assert v.kind == "free_text"
    assert v.token == "Multiple"
    assert v.line == 3


def test_legacy_context_outside_is_rejected():
    violations = _lint(_read_fixture("legacy_context_outside.txt"))
    print(f"legacy_context_outside.txt: {len(violations)} violation(s)")
    assert len(violations) == 1
    v = violations[0]
    assert v.kind == "free_text"
    assert v.line == 7
    assert v.count is not None and v.count >= 1


def test_legacy_correlation_outside_is_rejected():
    violations = _lint(_read_fixture("legacy_correlation_outside.txt"))
    print(f"legacy_correlation_outside.txt: {len(violations)} violation(s)")
    assert len(violations) == 1
    v = violations[0]
    assert v.kind == "free_text"
    assert v.token == "Accepted"
    assert v.line == 7


def test_legacy_marker_outside_is_rejected():
    violations = _lint(_read_fixture("legacy_marker_outside.txt"))
    print(f"legacy_marker_outside.txt: {len(violations)} violation(s)")
    assert len(violations) == 1
    v = violations[0]
    assert v.kind == "free_text"
    assert v.token == "truncated"
    assert v.line == 9


def test_v3_valid_prompt_is_clean():
    violations = _lint(_read_fixture("v3_valid.txt"))
    print(f"v3_valid.txt: {len(violations)} violation(s)")
    assert violations == []


# ───────────────────────────────────────────────── boundary edge cases
def test_block_with_wrong_nonce_is_content():
    other_nonce = "fedcba9876543210"
    good = B.untrusted("nothing free-text here", "context", nonce=NONCE)
    bad_tag = (
        f'<untrusted_data nonce="{other_nonce}" source="context">\n'
        "this must be rejected as free text\n"
        f'</untrusted_data nonce="{other_nonce}">'
    )
    message = good.rendered + "\n\n" + bad_tag
    violations = _lint(message)
    assert any(v.kind == "free_text" and v.token == "this" for v in violations)


def test_lookalike_bracket_block_is_content():
    # Fullwidth U+FF1C/FF1E, not the ASCII '<'/'>' the boundary regex requires.
    lookalike = (
        f'＜untrusted_data nonce="{NONCE}" source="context"＞\n'
        "hello\n"
        f'＜/untrusted_data nonce="{NONCE}"＞'
    )
    violations = _lint(lookalike)
    assert any(v.kind == "free_text" and v.token == "hello" for v in violations)


def test_unbalanced_block_is_a_violation():
    open_only = f'<untrusted_data nonce="{NONCE}" source="context">\nsome content\n'
    assert any(v.kind == "unbalanced_block" for v in _lint(open_only))

    close_only = f'some content\n</untrusted_data nonce="{NONCE}">'
    assert any(v.kind == "unbalanced_block" for v in _lint(close_only))


def test_tokens_enum_int_datetime_id_are_allowed():
    pb = B.PromptBuilder(system="sys", nonce=NONCE)
    pb.line(B.fact("severity", B.Severity.HIGH))
    pb.line(B.fact("occurrence_count", 7))
    pb.line(B.fact("alert_time", datetime(2026, 8, 16, 17, 56, 56, tzinfo=UTC)))
    pb.line(B.fact("agent_id", B.Id("agent_id", "001")))
    built = pb.build()
    assert _lint(built.user, nonce=built.nonce) == []


def test_first_token_and_line_are_reported():
    message = "## Alert\nseverity: critical\nrule: 40112 · Multiple bad words here\n"
    violations = _lint(message)
    free_text = [v for v in violations if v.kind == "free_text"]
    assert len(free_text) == 1
    assert free_text[0].token == "Multiple"
    assert free_text[0].line == 3
    assert free_text[0].count == 4


# ───────────────────────────────────────────────── every shipped template, and drift
def test_every_shipped_template_lints_clean():
    templates = sorted(TEMPLATES_DIR.glob("*.txt"))
    assert templates, "no templates shipped under app/llm/templates"
    for template_path in templates:
        template_path.read_text("utf-8")  # the system text; not linted (§7.2)
        nonce = B.wrap.new_nonce()
        user = _sample_v3_message(nonce)
        violations = L.lint(user, nonce=nonce, constants=B.TEMPLATE_CONSTANTS, enums=B.ENUM_VALUES)
        assert violations == [], f"{template_path.name}: {violations}"


def test_fixture_constants_are_the_builders():
    text = _read_fixture("v3_valid.txt")
    headings_in_fixture = [line for line in text.splitlines() if line.startswith("##")]
    assert headings_in_fixture, "fixture has no heading lines to check"
    for heading in headings_in_fixture:
        assert heading in B.TEMPLATE_CONSTANTS
    for sentence in (B.SENTENCE_ABSENT, B.SENTENCE_REQUEST_TRIAGE):
        assert sentence in B.TEMPLATE_CONSTANTS
        assert sentence in text
