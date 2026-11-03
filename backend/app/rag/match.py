"""Which approved entries are most like this alert or case: the Voyage rerank's selection (P14-T06, DEC-213,
spec §5.3 steps 6-7).

`candidates` and the vector search hand over at most 40 active entries, and the job has checked each against
its hash and its published file (V-R1, A4: an entry changed after approval reaches no prompt, this one
included). `score` sends the fingerprint's text as the query and each candidate's digest (`entry_digest`) as a
document to Voyage rerank, and gets a `relevance_score` from 0 to 1 per document. `keep` takes at most
`MAX_MATCHES` (3) of the best whose score reaches `RAG_MIN_SCORE`, and gives each a level from the two other
thresholds (`level_for`). Nothing here asks a model to rank: the P13 LLM ranker is gone from this module
(the draft job's own copy is `rag.draft_rank`).

**A `Match` is built from the candidate, never from the provider's reply** (spec §5.3 step 7): its `entry_id`
and `content_sha256` are the candidate's, its `level` comes from our thresholds, and the only thing taken from
Voyage is a number in [0, 1] that `rag.voyage.rerank` has already checked. A candidate the reply gave no score
is dropped, not given a neighbour's (Review Focus 1): results are mapped by `index`, never by position.

**The percentage** is `round(score * 100)` (`Match.pct`); it reaches ① and ② as the closed integer fact
`trung_pct` (`llm.builder`), after the level fact.

`entry_digest` is what leaves for Voyage and what the embed job stores a vector of (`web/rag_handlers/embed.py`):
the entry's closed fields (conclusion, category, MITRE ids, scenario, rule ids, tags), its title and its summary.
Never the sections after the summary (what tells it apart, what to check next time), which are for the analyst.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from app.infra.config import Config
from app.llm.builder import KbLearnedLevel
from app.rag import voyage
from app.rag.entries import Entry
from app.rag.fingerprint import Fingerprint

#: At most this many entries reach a prompt (spec §7.8; `llm.builder.MAX_LEARNED_ENTRIES` is the same bound).
MAX_MATCHES = 3
TITLE_LIMIT = 200


@dataclass(frozen=True)
class Match:
    """One kept match: closed values and a number, nothing the provider wrote. `score` is the rerank's
    relevance score in [0, 1]; `pct` is how the prompt and the page say it."""

    entry_id: str
    level: KbLearnedLevel
    content_sha256: str
    score: float

    @property
    def pct(self) -> int:
        return round(self.score * 100)


# ── the digest ────────────────────────────────────────────────────────────────────────────────


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
    """What Voyage reads of an entry: the closed fields it has (conclusion, category, MITRE ids, scenario,
    rule ids, tags), then its title and its summary, one `name: value` line each and a line left out when it
    has no value. The title and the summary are read from the entry's Markdown as `render_entry_markdown`
    writes it (`# <title>`, `## Tóm tắt`); an entry whose content has neither gives its closed fields only.
    Never the sections after the summary."""
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


# ── the levels, the score, the selection ──────────────────────────────────────────────────────


def level_for(score: float, cfg: Config) -> KbLearnedLevel | None:
    """The level a score earns: `rat_giong` from `RAG_LEVEL_RAT_GIONG`, `giong` from `RAG_LEVEL_GIONG`,
    `hoi_giong` from `RAG_MIN_SCORE`, and None below that (not a match). The thresholds are inclusive;
    a score that is not a number earns none."""
    if score >= cfg.RAG_LEVEL_RAT_GIONG:
        return KbLearnedLevel.RAT_GIONG
    if score >= cfg.RAG_LEVEL_GIONG:
        return KbLearnedLevel.GIONG
    if score >= cfg.RAG_MIN_SCORE:
        return KbLearnedLevel.HOI_GIONG
    return None


def score(
    fp: Fingerprint,
    cands: Sequence[Entry],
    *,
    cfg: Config,
    client: httpx.Client | None = None,
) -> tuple[list[tuple[Entry, float]], voyage.Usage]:
    """Rerank `cands` against `fp`: the query is the fingerprint's text, the documents are the candidates'
    digests in the candidates' order. Returns `(entry, relevance score)` best first, ties in the candidates'
    order, and what the call cost. A candidate the reply gave no score is not in the list. `RagUnavailable`
    reaches the caller (the lookup records its kind). With no candidates nothing is sent."""
    documents = [entry_digest(entry) for entry in cands]
    scores, usage = voyage.rerank(fp.text, documents, cfg=cfg, client=client)
    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [(cands[index], value) for index, value in ordered], usage


def keep(scored: Sequence[tuple[Entry, float]], cfg: Config) -> list[Match]:
    """At most `MAX_MATCHES` of `scored`, best first, each with the level its score earns; an entry
    below `RAG_MIN_SCORE` is not kept, and the places it would have taken go to the next that has a level.
    Sorting is stable, so equal scores keep the order given."""
    kept: list[Match] = []
    for entry, value in sorted(scored, key=lambda pair: -pair[1]):
        if len(kept) == MAX_MATCHES:
            break
        level = level_for(value, cfg)
        if level is None:
            continue
        kept.append(Match(entry.entry_id, level, entry.content_sha256, value))
    return kept
