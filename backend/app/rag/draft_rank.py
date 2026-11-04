"""The draft job's duplicate check: an LLM ranker over the candidates (P13-T03 `rag.match`, moved here by
P14-T06, DEC-213).

**This is not the lookup.** Since P14-T06 the `rag_lookup` job finds entries with Voyage embeddings and
scores them with Voyage rerank (`rag.match`, `rag.lookup`); it never asks a model to rank and has no
fallback to one. This module is the P13 ranking agent, unchanged in behaviour, kept for the one reader
that still needs it: `rag.draft`'s merge rule (P13-T04, spec §7.5), which asks "is this new draft a
duplicate of, or in conflict with, an approved entry rated `rat_giong`?" and has no Voyage call of its
own. The spec says the LLM is still used for drafts (DEC-213, spec §5.3 "What leaves the read path"). Its
schema and template were renamed with it (`draft_rank_v1`, `templates/draft_rank_system.txt`) so that nothing in
the lookup's code can be mistaken for the ranker it replaced.

`candidates` (a database search, no model) hands over at most 20 active entries, and the job has
checked each against its hash and its published file (V-R1, A4: an entry changed after approval reaches
no prompt, this one included). One DeepSeek call sees the fingerprint and a digest of each candidate,
every word of it inside an untrusted block, and answers `draft_rank_v1`: up to 3
`{entry_id, level, reason}`. This module builds that prompt, asks, and holds the answer to V-R1's
candidate membership and V-R2 (spec §7.7).

The prompt (`build_user`): a `context` block with the fingerprint, a `kb_learned` block per candidate
with the attribute `entry_id` (`wrap.untrusted_block` takes any text as an attribute; the builder's
`Id` has no shape for a uuid), then one request sentence, a template constant. Nothing else is outside
a block, and the linter checks that before the send (`rag.agent.call_json`).

A candidate's block is its digest (`match.entry_digest`), not its content. The whole user message is held to
`PROMPT_BUDGET_TOKENS` (`select_candidates`): the candidates at the end of the list, the lowest ordered, are
dropped until it fits, and the repair resends the same message.

The answer (`validate_matches`): a pick is kept when its `entry_id` is one of the candidates sent, that
entry is active, its `level` is one of the three, and the id is not a repeat; at most 3 are kept, the
first valid ones in the order the model gave them. Everything else is dropped and named in a fault,
`matches[<i>]: <name>` (or `matches: not_a_list`): `unknown_entry_id` (not a uuid), `not_a_candidate`,
`not_active`, `bad_level`, `duplicate`, `over_limit`, `not_an_object`. A fault never carries what the
model wrote. A `Pick` is built from the candidate, never from the model's text: its `entry_id` is the
candidate's and its `content_sha256` the candidate's stored hash.

The model's `reason` is returned apart, as `notes` (`entry_id -> reason`, one printable line of at most
160 characters), and is in no `Pick`, so it reaches no prompt (spec §7.7).
"""

from __future__ import annotations

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
from app.rag.match import MAX_MATCHES, entry_digest
from app.security import detector, wrap

SCHEMA_NAME = "draft_rank_v1"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "draft_rank_system.txt"
REASON_LIMIT = 160

#: The most a block holds, in bytes (`wrap.truncate_block` cuts the rest and says so inside the
#: block): the fingerprint's log is at most 2000 characters, and a digest is a few hundred.
CONTEXT_LIMIT_BYTES = 4_000
ENTRY_LIMIT_BYTES = 4_000

#: What the whole user message may come to, estimated with `llm.adapter.estimate_tokens` (2.5 bytes
#: a token, 30 KB). Well under ①'s `PROMPT_TOTAL_BUDGET_TOKENS`: a side call with a sub-cap of its own,
#: and the repair sends the same message again. `rag.draft` holds its own draft prompt to it too.
PROMPT_BUDGET_TOKENS = 12_000

#: The one sentence outside a block, a template constant for the linter.
SENTENCE_REQUEST_MATCH = "Trả về DUY NHẤT một đối tượng JSON theo schema draft_rank_v1."
EXTRA_CONSTANTS = frozenset({SENTENCE_REQUEST_MATCH})


@dataclass(frozen=True)
class Pick:
    """One kept pick: closed values only, nothing the model wrote. (`rag.match.Match` is the lookup's, with
    a score; the ranker gives none.)"""

    entry_id: str
    level: KbLearnedLevel
    content_sha256: str


@dataclass(frozen=True)
class _Kept:
    pick: Pick
    reason: str


def system_prompt() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


# ── the prompt ────────────────────────────────────────────────────────────────────────────────


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
            _Kept(Pick(cand.entry_id, level, cand.content_sha256), clean_reason(item.get("reason")))
        )
    return kept, faults


def validate_matches(raw: Any, cands: Sequence[Entry]) -> tuple[list[Pick], list[str]]:
    """V-R1's candidate membership and V-R2 over the answer `raw` (module doc): the picks kept,
    and the faults of the ones dropped, by name."""
    kept, faults = _validated(raw, cands)
    return [k.pick for k in kept], faults


def rank(
    adapter: Any, fp: Fingerprint, cands: Sequence[Entry], *, cfg: Config
) -> tuple[list[Pick], dict[str, str], agent.AgentResult]:
    """Ask which of `cands` are most like `fp`. Returns the picks kept, the notes (the model's reason
    for each kept pick, for the admin's page only) and the agent's result. Only the candidates that fit
    the prompt budget are sent (`select_candidates`), and only those can be picked. An answer the schema
    refused after the repair is no pick (`result.parsed` is None); an adapter failure reaches the caller.
    With no candidate to send nothing is asked."""
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
    return [k.pick for k in kept], {k.pick.entry_id: k.reason for k in kept}, result
