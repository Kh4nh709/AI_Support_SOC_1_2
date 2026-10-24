"""The ranking agent: which approved entries are most like this alert or case (P13-T03, spec §7.6).

`candidates` (a database search, no model) hands over at most 20 active entries, and the job has
checked each against its hash and its published file (V-R1, A4: an entry changed after approval reaches
no prompt, this one included). One DeepSeek call sees the fingerprint and a digest of each candidate,
every word of it inside an untrusted block, and answers `rag_match_v1`: up to 3
`{entry_id, level, reason}`. This module builds that prompt, asks, and holds the answer to V-R1's
candidate membership and V-R2 (spec §7.7).

The prompt (`build_user`): a `context` block with the fingerprint, a `kb_learned` block per candidate
with the attribute `entry_id` (`wrap.untrusted_block` takes any text as an attribute; the builder's
`Id` has no shape for a uuid), then one request sentence, a template constant. Nothing else is outside
a block, and the linter checks that before the send (`rag.agent.call_json`).

A candidate's block is its digest (`entry_digest`), not its content: its closed fields (conclusion,
category, MITRE ids, scenario, rule ids, tags), its title and its summary. Ranking needs no more, and
the sections that follow (what tells it apart, what to check next time) are for the analyst. The whole
user message is held to `PROMPT_BUDGET_TOKENS` (`select_candidates`): the candidates at the end of the
list, the lowest ordered, are dropped until it fits, and the repair resends the same message.

The answer (`validate_matches`): a match is kept when its `entry_id` is one of the candidates sent, that
entry is active, its `level` is one of the three, and the id is not a repeat; at most 3 are kept, the
first valid ones in the order the model gave them. Everything else is dropped and named in a fault,
`matches[<i>]: <name>` (or `matches: not_a_list`): `unknown_entry_id` (not a uuid), `not_a_candidate`,
`not_active`, `bad_level`, `duplicate`, `over_limit`, `not_an_object`. A fault never carries what the
model wrote. A `Match` is built from the candidate, never from the model's text: its `entry_id` is the
candidate's and its `content_sha256` the candidate's stored hash.

The model's `reason` is for the admin's page: `rank` returns it apart, as `match_notes`
(`entry_id -> reason`, one printable line of at most 160 characters), and it is in no `Match`, so it
reaches no prompt (spec §7.7).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.infra.config import Config
from app.llm.adapter import estimate_tokens
from app.llm.builder import KbLearnedLevel
from app.rag import agent
from app.rag.entries import Entry
from app.rag.fingerprint import Fingerprint
from app.security import detector, wrap

SCHEMA_NAME = "rag_match_v1"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "match_system.txt"
MAX_MATCHES = 3
REASON_LIMIT = 160

#: The most a block holds, in bytes (`wrap.truncate_block` cuts the rest and says so inside the
#: block): the fingerprint's log is at most 2000 characters, and a digest is a few hundred.
CONTEXT_LIMIT_BYTES = 4_000
ENTRY_LIMIT_BYTES = 4_000
TITLE_LIMIT = 200

#: What the whole user message may come to, estimated with `llm.adapter.estimate_tokens` (2.5 bytes
#: a token, 30 KB). Well under ①'s `PROMPT_TOTAL_BUDGET_TOKENS`: a lookup is a side call with a
#: sub-cap of its own, and the repair sends the same message again.
PROMPT_BUDGET_TOKENS = 12_000

#: The one sentence outside a block, a template constant for the linter.
SENTENCE_REQUEST_MATCH = "Trả về DUY NHẤT một đối tượng JSON theo schema rag_match_v1."
EXTRA_CONSTANTS = frozenset({SENTENCE_REQUEST_MATCH})


@dataclass(frozen=True)
class Match:
    """One kept match: closed values only, nothing the model wrote."""

    entry_id: str
    level: KbLearnedLevel
    content_sha256: str


@dataclass(frozen=True)
class _Kept:
    match: Match
    reason: str


def system_prompt() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


# ── the prompt ────────────────────────────────────────────────────────────────────────────────


_FRONT_MATTER_END = re.compile(r"^---[ \t]*$", re.MULTILINE)
_TITLE = re.compile(r"^# +(.+?)[ \t]*$", re.MULTILINE)
_SUMMARY = re.compile(r"^## Tóm tắt[ \t]*\n(.*?)(?=^## |\Z)", re.MULTILINE | re.DOTALL)


def _one_line(value: Any) -> str:
    return " ".join(str(value).split())


def _body(content: str) -> str:
    """The Markdown after the front matter (`render_entry_markdown` opens with it); nothing when
    the front matter is never closed."""
    if not content.startswith("---\n"):
        return content
    end = _FRONT_MATTER_END.search(content, 4)
    return content[end.end() :] if end else ""


def entry_digest(entry: Entry) -> str:
    """What the ranking agent reads of a candidate: the closed fields it has (conclusion, category,
    MITRE ids, scenario, rule ids, tags), then its title and its summary, one `name: value` line each
    and a line left out when it has no value. The title and the summary are read from the entry's
    Markdown as `render_entry_markdown` writes it (`# <title>`, `## Tóm tắt`); an entry whose content
    has neither gives its closed fields only. Never the sections after the summary."""
    lines = [f"conclusion: {_one_line(entry.conclusion)}", f"category: {_one_line(entry.category)}"]
    for name, values in (
        ("mitre", entry.mitre_ids),
        ("scenario", [entry.soar_scenario] if entry.soar_scenario else []),
        ("rules", entry.rule_ids),
        ("tags", entry.tags),
    ):
        if values:
            lines.append(f"{name}: {_one_line(' '.join(values))}")
    body = _body(entry.content)
    title = _TITLE.search(body)
    if title and _one_line(title.group(1)):
        lines.append(f"title: {_one_line(title.group(1))[:TITLE_LIMIT]}")
    summary = _SUMMARY.search(body)
    if summary and _one_line(summary.group(1)):
        lines.append(f"summary: {_one_line(summary.group(1))}")
    return "\n".join(lines)


def _blocks(fp: Fingerprint, cands: Sequence[Entry], nonce: str) -> list[wrap.Block]:
    context = wrap.untrusted_block(fp.text, "context", nonce=nonce, limit_bytes=CONTEXT_LIMIT_BYTES)
    entries = [
        wrap.untrusted_block(
            entry_digest(entry),
            "kb_learned",
            nonce=nonce,
            limit_bytes=ENTRY_LIMIT_BYTES,
            entry_id=entry.entry_id,
        )
        for entry in cands
    ]
    return [context, *entries]


def build_user(fp: Fingerprint, cands: Sequence[Entry], nonce: str) -> str:
    """The user message: the context block, a block per candidate in the order given, the request."""
    rendered = [block.rendered for block in _blocks(fp, cands, nonce)]
    return "\n\n".join([*rendered, SENTENCE_REQUEST_MATCH])


def select_candidates(fp: Fingerprint, cands: Sequence[Entry]) -> list[Entry]:
    """The longest prefix of `cands` whose user message fits `PROMPT_BUDGET_TOKENS`
    (`llm.adapter.estimate_tokens`, counted on the whole first message): the candidates at the end,
    the lowest ordered, are the ones dropped. A block is as long whatever the nonce is (always 16
    characters), so a stand-in nonce sizes the message the real one will make."""
    nonce = "0" * len(wrap.new_nonce())
    kept = list(cands)
    while kept and estimate_tokens(build_user(fp, kept, nonce)) > PROMPT_BUDGET_TOKENS:
        kept.pop()
    return kept


def injection_findings(fp: Fingerprint, cands: Sequence[Entry]) -> list[detector.Finding]:
    """The detector's findings over the blocks `build_user` renders for `cands`. They are recorded
    with the run and decide nothing (`security.detector`): an entry was approved by a person, and a
    log can say anything."""
    return detector.scan(_blocks(fp, cands, wrap.new_nonce()))


# ── the answer ────────────────────────────────────────────────────────────────────────────────


def _canonical_id(value: Any) -> str | None:
    """A uuid in the one spelling the database uses, or None."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


def _level(value: Any) -> KbLearnedLevel | None:
    if not isinstance(value, str):
        return None
    try:
        return KbLearnedLevel(value)
    except ValueError:
        return None


def clean_reason(value: Any) -> str:
    """One printable line of at most `REASON_LIMIT` characters. Control characters, a NUL and a
    lone surrogate (which PostgreSQL's jsonb refuses) become spaces, runs of space one space."""
    if not isinstance(value, str):
        return ""
    printable = "".join(ch if ch.isprintable() else " " for ch in value[: REASON_LIMIT * 4])
    return " ".join(printable.split())[:REASON_LIMIT].rstrip()


def _validated(raw: Any, cands: Sequence[Entry]) -> tuple[list[_Kept], list[str]]:
    items = raw.get("matches") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return [], ["matches: not_a_list"]
    by_id = {cand.entry_id: cand for cand in cands}
    kept: list[_Kept] = []
    faults: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        where = f"matches[{index}]"
        if not isinstance(item, dict):
            faults.append(f"{where}: not_an_object")
            continue
        entry_id = _canonical_id(item.get("entry_id"))
        if entry_id is None:
            faults.append(f"{where}: unknown_entry_id")
            continue
        cand = by_id.get(entry_id)
        if cand is None:
            faults.append(f"{where}: not_a_candidate")
            continue
        if cand.status != "active":
            faults.append(f"{where}: not_active")
            continue
        level = _level(item.get("level"))
        if level is None:
            faults.append(f"{where}: bad_level")
            continue
        if entry_id in seen:
            faults.append(f"{where}: duplicate")
            continue
        if len(kept) >= MAX_MATCHES:
            faults.append(f"{where}: over_limit")
            continue
        seen.add(entry_id)
        kept.append(
            _Kept(
                Match(cand.entry_id, level, cand.content_sha256), clean_reason(item.get("reason"))
            )
        )
    return kept, faults


def validate_matches(raw: Any, cands: Sequence[Entry]) -> tuple[list[Match], list[str]]:
    """V-R1's candidate membership and V-R2 over the answer `raw` (module doc): the matches kept,
    and the faults of the ones dropped, by name."""
    kept, faults = _validated(raw, cands)
    return [k.match for k in kept], faults


def rank(
    adapter: Any, fp: Fingerprint, cands: Sequence[Entry], *, cfg: Config
) -> tuple[list[Match], dict[str, str], agent.AgentResult]:
    """Ask which of `cands` are most like `fp`. Returns the matches kept, `match_notes` (the
    model's reason for each kept match, for the admin's page only) and the agent's result. Only the
    candidates that fit the prompt budget are sent (`select_candidates`), and only those can be
    matched. An answer the schema refused after the repair is no match (`result.parsed` is None); an
    adapter failure reaches the caller. With no candidate to send nothing is asked."""
    sent = select_candidates(fp, cands)
    if not sent:
        empty = agent.AgentResult(
            parsed={"matches": []}, schema_errors=[], usage={}, model=None, latency_ms=0
        )
        return [], {}, empty
    nonce = wrap.new_nonce()
    result = agent.call_json(
        adapter,
        system=system_prompt(),
        user=build_user(fp, sent, nonce),
        nonce=nonce,
        schema_name=SCHEMA_NAME,
        extra_constants=EXTRA_CONSTANTS,
        model=agent.rag_model(cfg),
        cfg=cfg,
    )
    if result.parsed is None:
        return [], {}, result
    kept, _faults = _validated(result.parsed, sent)
    return [k.match for k in kept], {k.match.entry_id: k.reason for k in kept}, result
