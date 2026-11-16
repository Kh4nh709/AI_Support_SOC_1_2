"""SR-T1 fix round 1 (C1 to C3) — `app.infra.storable`: the ONE test of "is this text storable" and the ONE way to make it so.

PostgreSQL cannot store a NUL character in a `text` or `jsonb` value, and a JSON text can carry an unpaired UTF-16 surrogate
(`"\\ud800"`, which a JavaScript string cut inside an emoji produces) that no UTF-8 encoder, the driver's or httpx's, accepts. Either one
reaching a write after something irreversible (a ticket's lock, n8n's action) made a 500, a ticket stuck in `processing`, or a
press that left no audit trace. The three doors that take outside text use this module: the webhook's reader (`review_notice`) refuses
such a body, the decision route refuses such a note, and the n8n client cleans such an answer.

Pure: no database.
"""

from __future__ import annotations

import pytest
from app.infra import storable

GOOD = [
    "",
    "plain",
    "Đã chặn 79.79.78.202 trên pfSense",
    "emoji 😀 as one character",
    "pair 😀".encode("utf-16", "surrogatepass").decode("utf-16"),  # a valid pair, joined
    "tab\tand\nnewline are storable",
    "\u200b\u202e invisible characters are storable: they are only removed where a name is compared",
    "� already a replacement character",
]
BAD = [
    "\x00",
    "a\x00b",
    "\ud800",  # a lone high surrogate
    "\udc00",  # a lone low surrogate
    "a\ud800b",
    "\ud83d",  # the first half of an emoji, cut
    "\ude00",  # the second half
    "\ude00\ud83d",  # a pair the wrong way round: two lone halves
    "x\x00\ud800y",
]


@pytest.mark.parametrize("text", GOOD, ids=repr)
def test_these_are_storable(text):
    assert storable.is_storable(text) is True
    assert storable.make_storable(text) == text


@pytest.mark.parametrize("text", BAD, ids=repr)
def test_these_are_not(text):
    assert storable.is_storable(text) is False


@pytest.mark.parametrize("text", BAD, ids=repr)
def test_making_one_storable_gives_a_storable_text(text):
    made = storable.make_storable(text)
    assert storable.is_storable(made) is True
    made.encode("utf-8")  # what the driver and httpx do: no UnicodeEncodeError


@pytest.mark.parametrize(
    "text,expected",
    [
        ("a\x00b", "ab"),  # a NUL is removed
        ("\x00\x00", ""),
        ("a\ud800b", "a�b"),  # a lone surrogate becomes U+FFFD
        ("\udc00\ud83d", "��"),
        ("x\x00\ud800y", "x�y"),
    ],
)
def test_nul_is_removed_and_a_lone_surrogate_becomes_the_replacement_character(text, expected):
    assert storable.make_storable(text) == expected


def test_a_valid_pair_is_not_touched():
    pair = "\U0001f600"
    assert storable.make_storable(f"a{pair}b") == f"a{pair}b"


def test_a_long_text_is_made_storable_in_one_pass():
    text = ("\x00\ud800ab" * 50_000)[:200_000]
    made = storable.make_storable(text)
    assert storable.is_storable(made) and len(made) == len(text) - text.count("\x00")
