"""The candidates the rerank chooses from (P13-T02, §7.6; P14-T06, DEC-213, spec §5.3 step 4).

**The database search**, `candidates`, is no model. At most `limit` (20) active entries, from two lists merged
without repeats:

* **closed-field overlap**: the entry's `category`, or one of its `mitre_ids`, or its `soar_scenario`
  is the fingerprint's (the category `unknown` is no overlap: an `unknown` entry is still a candidate
  by MITRE id, scenario or full text). Entries are ordered by how many of the three they share, then newest
  approval first;
* **full text**: the entries whose `fingerprint_tsv` (the `simple` configuration: no stemming, no
  stop words) holds a phrase of the fingerprint, ordered by `ts_rank_cd`. A phrase goes through
  `plainto_tsquery('simple', …)`, so its words are ANDed and its punctuation is never query syntax;
  phrases are ORed. The phrases are the fingerprint's rule ids and rule descriptions
  (`fingerprint.search_phrases`), not its log: a log carries a month and a counter that change every
  day, and a phrase that must match all of them would match nothing. This list catches the entry
  about the same rule whose category, MITRE ids or scenario are no longer the alert's.

Order of the merge: entries on both lists first (the overlap order), then the two remaining lists
taking turns, so that a long list of same-category entries cannot push every full-text hit out of
the cap.

Never a candidate: a retired entry; an entry whose `source_alert_ids` or `source_case_ids` meet the
exclusion (A5: the entry was drafted from the subject itself, its cluster or its case).

**The hybrid merge** (P14-T06, Director's call): the lookup also asks the vector database for the
`VECTOR_HITS` (20) entries nearest the fingerprint's embedding. `by_ids` reads those back from the main
database, which is the only source of an entry (spec §5.1): active and not excluded, so a vector row that
outlived its entry, and an entry drafted from the subject, are ignored. `hybrid` then puts the vector hits
first, in the vector search's order, and the database candidates after them, without repeats, at most
`MAX_CANDIDATES` (40). An exact rule-id or scenario match, which full text finds reliably, is never lost to an
embedding miss, and an entry that only the embedding found is never lost to the database search.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from itertools import zip_longest

import psycopg

from app.rag.entries import ENTRY_COLUMNS, Entry
from app.rag.fingerprint import Fingerprint, search_phrases
from app.rag.history import Exclusion, as_uuids

DEFAULT_LIMIT = 20
#: How many nearest entries the vector search is asked for, and how many candidates the rerank is given at most.
VECTOR_HITS = 20
MAX_CANDIDATES = 40
#: The category of an alert nothing resolved. Two of them share nothing, so it is no overlap.
UNKNOWN = "unknown"

_COLUMNS = ", ".join(f"e.{name}" for name in ENTRY_COLUMNS)
_NOT_EXCLUDED = (
    " AND NOT (e.source_alert_ids && %(skip_alerts)s::text[])"
    " AND NOT (e.source_case_ids && %(skip_cases)s::uuid[])"
)
_SHARES_CATEGORY = "CASE WHEN e.category = %(category)s THEN 1 ELSE 0 END"
_SHARES_MITRE = "CASE WHEN e.mitre_ids && %(mitre)s::text[] THEN 1 ELSE 0 END"
_SHARES_SCENARIO = (
    "CASE WHEN e.soar_scenario IS NOT NULL AND e.soar_scenario = %(scenario)s THEN 1 ELSE 0 END"
)

_OVERLAP = (
    f"SELECT {_COLUMNS} FROM knowledge_entries e WHERE e.status = 'active'"
    f" AND ({_SHARES_CATEGORY} + {_SHARES_MITRE} + {_SHARES_SCENARIO}) > 0"
    + _NOT_EXCLUDED
    + f" ORDER BY ({_SHARES_CATEGORY} + {_SHARES_MITRE} + {_SHARES_SCENARIO}) DESC,"
    " e.approved_at DESC NULLS LAST, e.entry_id LIMIT %(limit)s"
)
_FULL_TEXT = (
    f"SELECT {_COLUMNS} FROM knowledge_entries e"
    " JOIN (SELECT plainto_tsquery('simple', phrase) AS query"
    "       FROM unnest(%(phrases)s::text[]) AS phrase) q ON e.fingerprint_tsv @@ q.query"
    " WHERE e.status = 'active'" + _NOT_EXCLUDED + " GROUP BY e.entry_id"
    " ORDER BY max(ts_rank_cd(e.fingerprint_tsv, q.query)) DESC,"
    " e.approved_at DESC NULLS LAST, e.entry_id LIMIT %(limit)s"
)


def _merge(overlap: list[Entry], text: list[Entry], limit: int) -> list[Entry]:
    in_text = {entry.entry_id for entry in text}
    in_overlap = {entry.entry_id for entry in overlap}
    merged = [entry for entry in overlap if entry.entry_id in in_text]
    only_overlap = [entry for entry in overlap if entry.entry_id not in in_text]
    only_text = [entry for entry in text if entry.entry_id not in in_overlap]
    for from_overlap, from_text in zip_longest(only_overlap, only_text):
        if from_overlap is not None:
            merged.append(from_overlap)
        if from_text is not None:
            merged.append(from_text)
    return merged[:limit]


def candidates(
    conn: psycopg.Connection,
    fp: Fingerprint,
    exclusion: Exclusion,
    *,
    limit: int = DEFAULT_LIMIT,
) -> list[Entry]:
    """The entries the ranking agent may choose from (module doc). At most `limit`; `[]` for a
    limit that is not positive."""
    if limit <= 0:
        return []
    arguments = {
        "category": None if fp.category == UNKNOWN else fp.category,
        "mitre": list(fp.mitre_ids),
        "scenario": fp.soar_scenario,
        "skip_alerts": sorted(exclusion.alert_ids),
        "skip_cases": as_uuids(exclusion.case_ids),
        "limit": limit,
    }
    overlap = [Entry.from_row(row) for row in conn.execute(_OVERLAP, arguments).fetchall()]
    phrases = search_phrases(fp)
    text: list[Entry] = []
    if phrases:
        rows = conn.execute(_FULL_TEXT, {**arguments, "phrases": phrases}).fetchall()
        text = [Entry.from_row(row) for row in rows]
    return _merge(overlap, text, limit)


_BY_IDS = (
    f"SELECT {_COLUMNS} FROM knowledge_entries e WHERE e.status = 'active'"
    " AND e.entry_id = ANY(%(wanted)s::uuid[])" + _NOT_EXCLUDED
)


def by_ids(conn: psycopg.Connection, entry_ids: Iterable[str], exclusion: Exclusion) -> list[Entry]:
    """The active entries among `entry_ids`, read from the main database, in the order the ids were given
    (the vector search's order), each once. An id that names no entry, a retired entry, an entry drafted from
    the subject (A5, `exclusion`) and a value that is not a UUID are left out; the ids may be spelled in any
    way a UUID can be and the entries carry the canonical one."""
    ordered: list[uuid.UUID] = []
    for wanted in as_uuids(entry_ids):
        if wanted not in ordered:
            ordered.append(wanted)
    if not ordered:
        return []
    rows = conn.execute(
        _BY_IDS,
        {
            "wanted": ordered,
            "skip_alerts": sorted(exclusion.alert_ids),
            "skip_cases": as_uuids(exclusion.case_ids),
        },
    ).fetchall()
    found = {entry.entry_id: entry for entry in (Entry.from_row(row) for row in rows)}
    return [found[str(entry_id)] for entry_id in ordered if str(entry_id) in found]


def hybrid(
    vector_hits: Sequence[Entry], found: Sequence[Entry], *, limit: int = MAX_CANDIDATES
) -> list[Entry]:
    """The vector hits first, in their order, then the database candidates in theirs, no entry twice, at
    most `limit`. De-duplication comes before the cut, so a repeat never takes a place. `[]` for a limit that
    is not positive."""
    if limit <= 0:
        return []
    merged: list[Entry] = []
    seen: set[str] = set()
    for entry in (*vector_hits, *found):
        if entry.entry_id in seen:
            continue
        seen.add(entry.entry_id)
        merged.append(entry)
        if len(merged) == limit:
            break
    return merged
