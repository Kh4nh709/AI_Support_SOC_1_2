"""`app.security.invisible`: the code points a reader cannot see (moved out of `rag/draft.py` in the P13
whole-branch fix wave, because `llm/builder.py` needs the same table and `llm` imports no `rag`).

V1 refuses these in a draft (`tests/test_rag_draft.py` runs the draft through them); this file pins the
table itself: Unicode 15.0's `Default_Ignorable_Code_Point` plus the invisible code points that are not
default-ignorable, and the three general categories (Cf, Co, Cn).
"""

from __future__ import annotations

from app.rag import draft
from app.security import invisible


def test_the_table_is_unicode_15_default_ignorable_code_point_and_the_braille_blank() -> None:
    assert invisible.DEFAULT_IGNORABLE_RANGES == (
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x061C, 0x061C),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x206F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFF8),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0000, 0xE0FFF),
    )
    assert invisible.EXTRA_INVISIBLE_RANGES == ((0x2800, 0x2800),)
    assert invisible.INVISIBLE_RANGES == (
        *invisible.DEFAULT_IGNORABLE_RANGES,
        *invisible.EXTRA_INVISIBLE_RANGES,
    )


def test_every_code_point_of_the_table_is_deleted_and_refused() -> None:
    count = 0
    for low, high in invisible.INVISIBLE_RANGES:
        for cp in range(low, high + 1):
            char = chr(cp)
            assert invisible.is_invisible(char), hex(cp)
            assert invisible.strip_invisible(f"a{char}b") == "ab", hex(cp)
            assert draft._has_control(f"a{char}b"), hex(cp)
            count += 1
    assert count == len(invisible.INVISIBLE_CODE_POINTS) > 4_000  # no range overlaps another


def test_the_code_points_next_to_the_table_are_not_invisible() -> None:
    """Both ends of every range: the ordinary character beside it stays (hair space, hyphen,
    Hangul letters, Khmer vowels, a Khmer-adjacent mark, the next braille cell)."""
    beside = [
        0x00AC, 0x00AE, 0x034E, 0x0350, 0x061B, 0x061D, 0x115E, 0x1161, 0x17B3, 0x17B6, 0x180A,
        0x1810, 0x200A, 0x2010, 0x2029, 0x202F, 0x205F, 0x2070, 0x3163, 0x3165, 0xFE10, 0xFFA1,
        0x2801, 0x27FF,
    ]  # fmt: skip
    for cp in beside:
        char = chr(cp)
        assert not invisible.is_invisible(char), hex(cp)
        assert invisible.strip_invisible(f"a{char}b") == f"a{char}b", hex(cp)
