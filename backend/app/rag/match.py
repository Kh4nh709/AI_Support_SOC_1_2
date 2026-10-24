"""The ranking agent: which approved entries are most like this alert or case (P13-T03, spec §7.6).

`candidates` (a database search, no model) hands over at most 20 active entries. One DeepSeek call
sees the fingerprint and their content, every word of it inside an untrusted block, and answers
`rag_match_v1`: up to 3 `{entry_id, level, reason}`. This module builds that prompt, asks, and holds
the answer to V-R1's candidate membership and V-R2 (spec §7.7); the published file's hash, the other
half of V-R1, is the job's (`rag.lookup`).

The prompt (`build_user`): a `context` block with the fingerprint, a `kb_learned` block per candidate
with the attribute `entry_id` (`wrap.untrusted_block` takes any text as an attribute; the builder's
`Id` has no shape for a uuid), then one request sentence, a template constant. Nothing else is outside
a block, and the linter checks that before the send (`rag.agent.call_json`).

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

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.infra.config import Config
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
#: block): twenty entries must fit one call, and the fingerprint's log is at most 2000 characters.
CONTEXT_LIMIT_BYTES = 4_000
ENTRY_LIMIT_BYTES = 6_000

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


def _blocks(fp: Fingerprint, cands: Sequence[Entry], nonce: str) -> list[wrap.Block]:
    context = wrap.untrusted_block(fp.text, "context", nonce=nonce, limit_bytes=CONTEXT_LIMIT_BYTES)
    entries = [
        wrap.untrusted_block(
            entry.content,
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


def injection_findings(fp: Fingerprint, cands: Sequence[Entry]) -> list[detector.Finding]:
    """The detector's findings over the blocks `build_user` renders. They are recorded with the run
    and decide nothing (`security.detector`): an entry was approved by a person, and a log can say
    anything."""
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
    model's reason for each kept match, for the admin's page only) and the agent's result. An answer
    the schema refused after the repair is no match (`result.parsed` is None); an adapter failure
    reaches the caller. With no candidate nothing is asked."""
    if not cands:
        empty = agent.AgentResult(
            parsed={"matches": []}, schema_errors=[], usage={}, model=None, latency_ms=0
        )
        return [], {}, empty
    nonce = wrap.new_nonce()
    result = agent.call_json(
        adapter,
        system=system_prompt(),
        user=build_user(fp, cands, nonce),
        nonce=nonce,
        schema_name=SCHEMA_NAME,
        extra_constants=EXTRA_CONSTANTS,
        model=agent.rag_model(cfg),
        cfg=cfg,
    )
    if result.parsed is None:
        return [], {}, result
    kept, _faults = _validated(result.parsed, cands)
    return [k.match for k in kept], {k.match.entry_id: k.reason for k in kept}, result
