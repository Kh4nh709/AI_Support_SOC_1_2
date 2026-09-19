"""Regex/heuristic injection detector; its findings are recorded but never change a verdict.

`scan(blocks) -> list[Finding]` runs over block *contents* (`block.plain`, the
normalised text the model effectively reads) — never over the assembled
prompt, which would also match the template's own instructions. Findings are
recorded to `llm_runs.injection_findings` for measurement and display
(context pack §7.3 step 5 / `docs/plan/tasks/P3/P3-tasks.md` planning
decision 13). This module has no notion of a verdict and never mutates its
input.

`docs/phase-5-auto-triage.md:84-106` describes a v1 three-layer defence whose
third layer forced one specific outcome outright once detection reached its
high level. That layer is **not implemented here** — v3 §4.2 (the
architecture doc, §4.2) replaced it: no detector sits upstream of the gate,
and this module's output is measured and displayed, nothing more.

20 patterns = 19 ported verbatim from `Final-Project`'s
`prompt_guard.py:60-80` (DEC-002: detection-only, stdlib, never mutates —
measured clean; read-only reference, outside this repository, never
imported, never vendored) plus one Vietnamese instruction-override addition.
3 heuristics ported from the same source (`_BASE64_RUN`,
`_find_proximity_matches`, and the hidden-character check that in the
reference lived inside `_PATTERNS` itself); 5 new heuristics.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from app.security.wrap import TRUNCATION_MARKER, Block

_MATCH_CAP = 80


@dataclass(frozen=True)
class Finding:
    category: str  # instruction_override | role_override | fake_role_marker | prompt_exfiltration |
    # forbidden_action_request | delimiter_escape_attempt | obfuscation_hidden_chars |
    # possible_obfuscation | nonce_shaped_token | fake_truncation_marker |
    # role_marker_flood | imperative_density
    pattern: str  # the regex source or "heuristic:<name>"
    matched_text: str  # <=80 chars of the match -- attacker text; stored in llm_runs, never printed
    source: str  # the block source it was found in
    level: str  # "high" | "medium"


# The 19 pairs ported verbatim (same regex source, same category names) from
# prompt_guard.py:60-78, in file order, plus the 20th: a Vietnamese
# instruction-override pattern using the phrase phase-5 itself uses as its
# example (docs/phase-5-auto-triage.md:86, "Bo qua huong dan truoc do...").
_PATTERN_SOURCES: list[tuple[str, str]] = [
    (
        r"ignore\s+(all\s+|any\s+|previous\s+|prior\s+|the\s+above\s+){1,2}instructions?",
        "instruction_override",
    ),
    (r"disregard\s+(all|any|previous|prior|the\s+above)", "instruction_override"),
    (r"forget\s+(all|everything|your\s+instructions)", "instruction_override"),
    (r"new\s+(system\s+)?instructions?\s*[:\-]", "instruction_override"),
    (r"override\s+safety", "instruction_override"),
    (r"you\s+are\s+now\s+(a|an)?\s*\w+", "role_override"),
    (r"act\s+as\s+(a|an)\s+(unrestricted|jailbroken|different)", "role_override"),
    (r"pretend\s+(you\s+are|to\s+be)", "role_override"),
    (r"^\s*(system|assistant|human)\s*:", "fake_role_marker"),
    (r"<\|(system|im_start|im_end|assistant|user)\|?>", "fake_role_marker"),
    (r"```\s*(system|instructions?)", "fake_role_marker"),
    (r"reveal\s+(your|the)\s+(system\s+)?prompt", "prompt_exfiltration"),
    (r"print\s+(your|the)\s+(system\s+)?prompt", "prompt_exfiltration"),
    (r"what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions)", "prompt_exfiltration"),
    (r"execute\s+(this|the\s+following)\s+(command|script)", "forbidden_action_request"),
    (r"auto-?approve", "forbidden_action_request"),
    (r"<<<\s*/?\s*(END_)?UNTRUSTED_DATA", "delimiter_escape_attempt"),
    (r"</?(system|instructions?|untrusted_data)>", "delimiter_escape_attempt"),
    (r"[\u200b\u200c\u200d\ufeff]", "obfuscation_hidden_chars"),
    (
        r"(bỏ qua|quên|phớt lờ)\s+(mọi|tất cả|các)?\s*(hướng dẫn|chỉ thị|lệnh)\s*(trước|ở trên|trên)",
        "instruction_override",
    ),
]

# design note 2: every regex category is "high" except obfuscation_hidden_chars ("medium" on its own).
_REGEX_CATEGORY_LEVEL: dict[str, str] = {
    "instruction_override": "high",
    "role_override": "high",
    "fake_role_marker": "high",
    "prompt_exfiltration": "high",
    "forbidden_action_request": "high",
    "delimiter_escape_attempt": "high",
    "obfuscation_hidden_chars": "medium",
}

PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(source, re.IGNORECASE | re.MULTILINE), category)
    for source, category in _PATTERN_SOURCES
]


# ---------------------------------------------------------------------------
# heuristics — each is its own function, taking the Block and returning raw
# (category, pattern_name, matched_text, level) tuples. `scan` calls them in
# this order, after the regexes.
# ---------------------------------------------------------------------------

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def _heuristic_base64_run(block: Block) -> list[tuple[str, str, str, str]]:
    return [
        ("possible_obfuscation", "heuristic:base64_run", m.group(0)[:_MATCH_CAP], "medium")
        for m in _BASE64_RUN.finditer(block.plain)
    ]


_PROXIMITY_VERBS = ("block", "delete", "quarantine", "resolve", "approve")
_PROXIMITY_QUALIFIERS = (
    "automatically",
    "immediately",
    "without review",
    "without approval",
    "no review",
    "without waiting",
)
_PROXIMITY_WINDOW = 60


def _heuristic_proximity(block: Block) -> list[tuple[str, str, str, str]]:
    findings: list[tuple[str, str, str, str]] = []
    lowered = block.plain.lower()
    for verb in _PROXIMITY_VERBS:
        for vm in re.finditer(r"\b" + re.escape(verb) + r"\b", lowered):
            start = max(0, vm.start() - _PROXIMITY_WINDOW)
            end = min(len(lowered), vm.end() + _PROXIMITY_WINDOW)
            window = lowered[start:end]
            for qualifier in _PROXIMITY_QUALIFIERS:
                if qualifier in window:
                    findings.append(
                        (
                            "forbidden_action_request",
                            f"heuristic:proximity({verb!r}, {qualifier!r})",
                            block.plain[start:end][:_MATCH_CAP],
                            "high",
                        )
                    )
                    break
    return findings


_HIDDEN_CHARS = re.compile(r"[\u200b\u200c\u200d\ufeff]")


def _heuristic_hidden_chars(block: Block) -> list[tuple[str, str, str, str]]:
    return [
        ("obfuscation_hidden_chars", "heuristic:hidden_chars", m.group(0)[:_MATCH_CAP], "medium")
        for m in _HIDDEN_CHARS.finditer(block.plain)
    ]


_DELIMITER_LOOKALIKE_NEEDLES = ("</untrusted_data", "<untrusted_data")


def _heuristic_delimiter_lookalike(block: Block) -> list[tuple[str, str, str, str]]:
    folded = unicodedata.normalize("NFKC", block.plain)
    findings: list[tuple[str, str, str, str]] = []
    for needle in _DELIMITER_LOOKALIKE_NEEDLES:
        idx = folded.find(needle)
        if idx != -1:
            findings.append(
                (
                    "delimiter_escape_attempt",
                    "heuristic:delimiter_lookalike",
                    folded[idx : idx + _MATCH_CAP],
                    "high",
                )
            )
    return findings


_HEX16 = re.compile(r"\b[0-9a-fA-F]{16}\b")
_NONCE_WORD = re.compile(r"\bnonce\b", re.IGNORECASE)
_NONCE_PROXIMITY_WINDOW = 40


def _heuristic_nonce_shaped_token(block: Block) -> list[tuple[str, str, str, str]]:
    text = block.plain
    findings: list[tuple[str, str, str, str]] = []
    for nm in _NONCE_WORD.finditer(text):
        start = max(0, nm.start() - _NONCE_PROXIMITY_WINDOW)
        end = min(len(text), nm.end() + _NONCE_PROXIMITY_WINDOW)
        for hm in _HEX16.finditer(text[start:end]):
            findings.append(
                (
                    "nonce_shaped_token",
                    "heuristic:nonce_shaped_token",
                    hm.group(0)[:_MATCH_CAP],
                    "medium",
                )
            )
    return findings


def _heuristic_fake_truncation_marker(block: Block) -> list[tuple[str, str, str, str]]:
    count = block.plain.count(TRUNCATION_MARKER)
    is_fake = (not block.truncated and count >= 1) or (block.truncated and count > 1)
    if not is_fake:
        return []
    return [
        (
            "fake_truncation_marker",
            "heuristic:fake_truncation_marker",
            TRUNCATION_MARKER,
            "medium",
        )
    ]


_ROLE_MARKER_LINE = re.compile(
    r"^\s*(system|assistant|user|human)\s*:", re.IGNORECASE | re.MULTILINE
)
_ROLE_MARKER_FLOOD_MIN = 3


def _heuristic_role_marker_flood(block: Block) -> list[tuple[str, str, str, str]]:
    matches = list(_ROLE_MARKER_LINE.finditer(block.plain))
    if len(matches) < _ROLE_MARKER_FLOOD_MIN:
        return []
    summary = "; ".join(m.group(0).strip() for m in matches)
    return [("role_marker_flood", "heuristic:role_marker_flood", summary[:_MATCH_CAP], "high")]


# design note 3(8): 20-word imperative list, English and Vietnamese.
_IMPERATIVE_WORDS = (
    "ignore",
    "disregard",
    "forget",
    "override",
    "execute",
    "classify",
    "mark",
    "set",
    "disable",
    "reveal",
    "bỏ qua",
    "hãy",
    "đánh dấu",
    "phân loại",
    "quên",
    "phớt lờ",
    "thực thi",
    "tắt",
    "đặt",
    "tiết lộ",
)
_IMPERATIVE_WORDS_LOWER = tuple(w.lower() for w in _IMPERATIVE_WORDS)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")
_IMPERATIVE_DENSITY_MIN_HITS = 3
_IMPERATIVE_DENSITY_MAX_SENTENCES = 20


def _heuristic_imperative_density(block: Block) -> list[tuple[str, str, str, str]]:
    sentences = [s.strip() for s in _SENTENCE_SPLIT.split(block.plain) if s.strip()]
    if not sentences or len(sentences) > _IMPERATIVE_DENSITY_MAX_SENTENCES:
        return []
    hits = [s for s in sentences if s.lower().startswith(_IMPERATIVE_WORDS_LOWER)]
    if len(hits) < _IMPERATIVE_DENSITY_MIN_HITS:
        return []
    summary = "; ".join(hits)
    return [("imperative_density", "heuristic:imperative_density", summary[:_MATCH_CAP], "medium")]


HEURISTICS = (
    _heuristic_base64_run,
    _heuristic_proximity,
    _heuristic_hidden_chars,
    _heuristic_delimiter_lookalike,
    _heuristic_nonce_shaped_token,
    _heuristic_fake_truncation_marker,
    _heuristic_role_marker_flood,
    _heuristic_imperative_density,
)


def scan(blocks: Iterable[Block]) -> list[Finding]:
    """Findings only — never mutates `blocks`, never raises, never decides."""
    findings: list[Finding] = []
    for block in blocks:
        if not isinstance(block.plain, str):
            continue  # design note 4: None/bytes/int text is no text -- no findings, no raise
        text = block.plain
        source = block.source if isinstance(block.source, str) else ""
        regex_findings = [
            Finding(
                category=category,
                pattern=pattern.pattern,
                matched_text=m.group(0)[:_MATCH_CAP],
                source=source,
                level=_REGEX_CATEGORY_LEVEL[category],
            )
            for pattern, category in PATTERNS
            for m in pattern.finditer(text)
        ]
        findings.extend(regex_findings)
        # design note 6 (DEC-092): a heuristic that rediscovers a regex hit on the
        # same (source, category, matched_text) is a duplicate, not a second finding.
        seen = {(f.source, f.category, f.matched_text) for f in regex_findings}
        for heuristic in HEURISTICS:
            for category, pattern_name, matched_text, finding_level in heuristic(block):
                matched_text = matched_text[:_MATCH_CAP]
                if (source, category, matched_text) in seen:
                    continue
                findings.append(
                    Finding(
                        category=category,
                        pattern=pattern_name,
                        matched_text=matched_text,
                        source=source,
                        level=finding_level,
                    )
                )
    return findings


def level(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    if any(f.level == "high" for f in findings):
        return "high"
    if any(f.level == "medium" for f in findings):
        return "medium"
    return "none"


def as_json(findings: Iterable[Finding]) -> list[dict]:
    return [
        {
            "category": f.category,
            "pattern": f.pattern,
            "matched_text": f.matched_text,
            "source": f.source,
            "level": f.level,
        }
        for f in findings
    ]
