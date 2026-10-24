"""The candidates the ranking agent chooses from: a database search, not a model (P13-T02, §7.6).

At most `limit` (20) active entries, from two lists merged without repeats:

* **closed-field overlap**: the entry's `category`, or one of its `mitre_ids`, or its `soar_scenario`
  is the fingerprint's. Entries are ordered by how many of the three they share, then newest
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
"""

from __future__ import annotations

from itertools import zip_longest

import psycopg

from app.rag.entries import ENTRY_COLUMNS, Entry
from app.rag.fingerprint import Fingerprint, search_phrases
from app.rag.history import Exclusion, as_uuids

DEFAULT_LIMIT = 20

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
        "category": fp.category,
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
