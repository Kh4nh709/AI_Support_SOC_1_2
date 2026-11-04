"""P14-T06 / DEC-213, spec §5.3 step 4 — `rag.candidates.hybrid`: the vector hits and the database candidates
merged into one list.

Pure: the entries are plain `Entry` objects. The rule (Director's call, spec §5.3): the vector hits come first,
in the vector search's order; then the database candidates (closed-field overlap and full text, `candidates()`)
in their own order; no entry twice; at most 40. So an exact rule-id or scenario match, which full text finds
reliably, is never lost to an embedding miss, and an entry only the embedding found is never lost to the
database search.
"""

from __future__ import annotations

import uuid

import pytest
from app.rag import candidates
from app.rag.entries import Entry

from tests.test_rag_match import make_entry


def ids(found: list[Entry]) -> list[str]:
    return [entry.entry_id for entry in found]


def entries(n: int) -> list[Entry]:
    return [make_entry(str(uuid.uuid4())) for _ in range(n)]


def test_the_limits_are_twenty_and_twenty_and_forty() -> None:
    assert candidates.VECTOR_HITS == 20
    assert candidates.DEFAULT_LIMIT == 20
    assert candidates.MAX_CANDIDATES == 40


def test_the_vector_hits_come_first_in_their_order_then_the_database_ones_in_theirs() -> None:
    v1, v2, v3 = entries(3)
    d1, d2 = entries(2)
    assert ids(candidates.hybrid([v1, v2, v3], [d1, d2])) == ids([v1, v2, v3, d1, d2])


def test_an_entry_found_by_both_is_listed_once_at_its_vector_place() -> None:
    v1, v2 = entries(2)
    d1 = entries(1)[0]
    merged = candidates.hybrid([v1, v2], [d1, v2, v1])
    assert ids(merged) == ids([v1, v2, d1])


def test_the_same_entry_twice_in_one_list_is_one() -> None:
    v1 = entries(1)[0]
    assert ids(candidates.hybrid([v1, v1], [v1])) == [v1.entry_id]


def test_the_database_candidates_alone_are_kept_when_the_vector_search_found_nothing() -> None:
    d1, d2 = entries(2)
    assert ids(candidates.hybrid([], [d1, d2])) == ids([d1, d2])


def test_the_vector_hits_alone_are_kept_when_the_database_found_nothing() -> None:
    v1, v2 = entries(2)
    assert ids(candidates.hybrid([v1, v2], [])) == ids([v1, v2])


def test_nothing_is_nothing() -> None:
    assert candidates.hybrid([], []) == []


def test_at_most_forty_and_the_cut_takes_the_database_tail_not_the_vector_head() -> None:
    vec = entries(20)
    db = entries(30)
    merged = candidates.hybrid(vec, db)
    assert len(merged) == candidates.MAX_CANDIDATES == 40
    assert ids(merged)[:20] == ids(vec)
    assert ids(merged)[20:] == ids(db[:20])


def test_de_duplication_happens_before_the_cut() -> None:
    vec = entries(20)
    db = [*vec[:10], *entries(30)]  # ten repeats, then thirty new ones
    merged = candidates.hybrid(vec, db)
    assert len(merged) == 40 and len(set(ids(merged))) == 40
    assert ids(merged)[20:] == ids(db[10:30])


def test_the_limit_is_a_parameter() -> None:
    vec, db = entries(3), entries(3)
    assert ids(candidates.hybrid(vec, db, limit=4)) == ids([*vec, db[0]])
    assert candidates.hybrid(vec, db, limit=0) == []


@pytest.mark.parametrize("limit", [-1, -40])
def test_a_limit_that_is_not_positive_is_nothing(limit) -> None:
    assert candidates.hybrid(entries(2), entries(2), limit=limit) == []
