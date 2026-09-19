"""Verify every character outside an untrusted_data block is a template constant, enum or id."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

# Duplicated from `app.llm.builder.ID_PATTERNS`, not imported: `security` may not
# import `llm` (context pack §4/G1). `test_ids_match_the_builders_patterns` is what
# keeps this copy from drifting out of step with the builder's.
_ID_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\d+\.\d+$"),  # alert_id
    re.compile(r"^\d+$"),  # rule_id
    re.compile(r"^T\d{4}(\.\d{3})?$"),  # mitre
    re.compile(r"^\d{3,}$"),  # agent_id
    re.compile(r"^[a-z]{2,6}-\d{1,2}$"),  # rule_ref (decision-table rule ids, e.g. sbf-1)
)
_INT_RE = re.compile(r"^-?\d+$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

# design note 1.3's separator characters. A token's edges are trimmed of these —
# never the middle, which would shred a datetime's dashes/colons/dot, an alert_id's
# dot, or a rule_ref's dash into fragments none of which would pass on its own.
_EDGE_CHARS = "·-:,.()[]#→∈∧≠"
_BARE_EQUALS = "="


@dataclass(frozen=True)
class Violation:
    kind: str  # "unbalanced_block" | "free_text"
    token: str | None = None
    line: int | None = None
    count: int | None = None


def _line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _strip_blocks(text: str, nonce: str) -> tuple[str, list[Violation]]:
    """Remove every `<untrusted_data nonce=NONCE …>…</untrusted_data nonce=NONCE>`
    span, pairing tags in document order (blocks never nest — `wrap.untrusted_block`
    is the only thing that emits one). A tag carrying a different nonce, no nonce,
    or a look-alike bracket matches neither regex and is left in the residual, where
    it fails as free text — the boundary's authority comes from the nonce, not the
    shape (context pack §7.1)."""
    escaped = re.escape(nonce)
    combined = re.compile(
        rf'(?P<open><untrusted_data nonce="{escaped}"[^>]*>)'
        rf'|(?P<close></untrusted_data nonce="{escaped}">)'
    )

    violations: list[Violation] = []
    spans: list[tuple[int, int]] = []
    pending_start: int | None = None
    for m in combined.finditer(text):
        if m.lastgroup == "open":
            if pending_start is not None:
                violations.append(
                    Violation(kind="unbalanced_block", line=_line_at(text, pending_start))
                )
            pending_start = m.start()
        else:
            if pending_start is None:
                violations.append(
                    Violation(kind="unbalanced_block", line=_line_at(text, m.start()))
                )
            else:
                spans.append((pending_start, m.end()))
                pending_start = None
    if pending_start is not None:
        violations.append(Violation(kind="unbalanced_block", line=_line_at(text, pending_start)))

    # Replace each matched span with the same count of newlines it contained, so
    # every later line number still names the same line in the original text.
    parts: list[str] = []
    last = 0
    for start, end in spans:
        parts.append(text[last:start])
        parts.append("\n" * text.count("\n", start, end))
        last = end
    parts.append(text[last:])
    return "".join(parts), violations


def _strip_constants(text: str, constants: Iterable[str]) -> str:
    """Remove every occurrence of each multi-character constant, longest first, so
    a constant that contains another (e.g. a heading containing '±2h') is removed
    whole. The two single-character structural glyphs among `TEMPLATE_CONSTANTS`
    ('-' the bullet, '·' the field separator) are deliberately left for the
    tokenizer's per-token edge-trim below: a blind whole-text replace of either
    would also eat the dashes inside a datetime or a rule_ref id, or the dot inside
    an alert_id, anywhere else in the residual."""
    for constant in sorted({c for c in constants if len(c) > 1}, key=len, reverse=True):
        text = text.replace(constant, "")
    return text


def _is_allowed_token(token: str, enums: frozenset[str]) -> bool:
    if token in enums:
        return True
    if _INT_RE.fullmatch(token):
        return True
    if _DATETIME_RE.fullmatch(token):
        return True
    if any(pattern.fullmatch(token) for pattern in _ID_PATTERNS):
        return True
    return token == _BARE_EQUALS


def _line_violation(line_text: str, line_no: int, enums: frozenset[str]) -> Violation | None:
    first_token: str | None = None
    count = 0
    for raw in line_text.split():
        core = raw.strip(_EDGE_CHARS)
        if not core:
            continue
        if _is_allowed_token(core, enums):
            continue
        count += 1
        if first_token is None:
            first_token = core[:40]
    if count == 0:
        return None
    return Violation(kind="free_text", token=first_token, line=line_no, count=count)


def lint(
    user_message: str,
    *,
    nonce: str,
    constants: Iterable[str],
    enums: Iterable[str],
) -> list[Violation]:
    """An independent parser of `user_message`: strip every block carrying `nonce`,
    strip `constants`, then every residual token must be an enum value (from
    `enums`), an integer, an ISO-8601 datetime, or an id — anything else is a
    `free_text` violation. Pure: no Config, no DB, no I/O (design note 5)."""
    residual, violations = _strip_blocks(user_message, nonce)
    residual = _strip_constants(residual, constants)
    enum_set = frozenset(enums)
    for line_no, line_text in enumerate(residual.split("\n"), start=1):
        violation = _line_violation(line_text, line_no, enum_set)
        if violation is not None:
            violations.append(violation)
    return violations
