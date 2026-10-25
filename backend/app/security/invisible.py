"""Code points a reader cannot see, or sees as something else (P13-T04, moved here in the P13 fix wave).

Text that carries them can hold an instruction or a literal that the admin reviewing a draft does not
see, and that `security.detector` (four code points) and V3 (a literal split by one) miss. It lives in
`security`, not in `rag`, because `llm/builder.py` reads approved text at prompt time with the same eyes
as V4 (`llm` imports no `rag`). Two tests, either of which makes a code point invisible:

* the Unicode general category is format (Cf: tag characters, bidi controls, soft hyphen, word
  joiner, zero-width characters, the BOM, the Arabic number sign), private use (Co) or unassigned (Cn);
* the code point is in `INVISIBLE_RANGES`: the Unicode `Default_Ignorable_Code_Point` property,
  which also holds characters that are NOT Cf, such as the variation selectors (Mn: U+FE00-FE0F, and
  U+E0100-E01EF, which can smuggle a whole instruction behind one emoji, while U+FE0F alone splits an
  address), the combining grapheme joiner (Mn), the Hangul fillers (Lo) and the Mongolian and Khmer
  ones, plus the code points that draw nothing though they are not default-ignorable (`EXTRA_INVISIBLE_RANGES`).

`strip_invisible` deletes them (it does not replace them with a space): `79.79<U+2060>.78.202` becomes
the address it displays as.
"""

from __future__ import annotations

import unicodedata

_INVISIBLE_CATEGORIES = frozenset({"Cf", "Co", "Cn"})

#: `Default_Ignorable_Code_Point`, Unicode 15.0, `DerivedCoreProperties.txt`, as inclusive ranges. A
#: hard-coded table: `unicodedata` has no such property, and a table does not move with the
#: interpreter's Unicode version (the category test above does, in the safe direction: a code point
#: assigned later is still stripped as long as it is in a range here).
DEFAULT_IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),  # SOFT HYPHEN
    (0x034F, 0x034F),  # COMBINING GRAPHEME JOINER
    (0x061C, 0x061C),  # ARABIC LETTER MARK
    (0x115F, 0x1160),  # HANGUL CHOSEONG FILLER, HANGUL JUNGSEONG FILLER
    (0x17B4, 0x17B5),  # KHMER VOWEL INHERENT AQ, AA
    (0x180B, 0x180F),  # MONGOLIAN FREE VARIATION SELECTORS, VOWEL SEPARATOR
    (0x200B, 0x200F),  # ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),  # LEFT-TO-RIGHT EMBEDDING .. RIGHT-TO-LEFT OVERRIDE
    (0x2060, 0x206F),  # WORD JOINER .. NOMINAL DIGIT SHAPES
    (0x3164, 0x3164),  # HANGUL FILLER
    (0xFE00, 0xFE0F),  # VARIATION SELECTOR-1..16
    (0xFEFF, 0xFEFF),  # ZERO WIDTH NO-BREAK SPACE (the BOM)
    (0xFFA0, 0xFFA0),  # HALFWIDTH HANGUL FILLER
    (0xFFF0, 0xFFF8),  # reserved
    (0x1BCA0, 0x1BCA3),  # SHORTHAND FORMAT LETTER OVERLAP .. UP STEP
    (0x1D173, 0x1D17A),  # MUSICAL SYMBOL BEGIN BEAM .. END PHRASE
    (0xE0000, 0xE0FFF),  # tag characters, VARIATION SELECTOR-17..256, reserved
)
#: Invisible though not default-ignorable: BRAILLE PATTERN BLANK, which draws a blank cell.
EXTRA_INVISIBLE_RANGES: tuple[tuple[int, int], ...] = ((0x2800, 0x2800),)
INVISIBLE_RANGES = (*DEFAULT_IGNORABLE_RANGES, *EXTRA_INVISIBLE_RANGES)
INVISIBLE_CODE_POINTS = frozenset(
    code_point for low, high in INVISIBLE_RANGES for code_point in range(low, high + 1)
)


def is_invisible(char: str) -> bool:
    return ord(char) in INVISIBLE_CODE_POINTS or unicodedata.category(char) in _INVISIBLE_CATEGORIES


def strip_invisible(text: str) -> str:
    """`text` without its invisible code points (`is_invisible`), which are deleted, not
    replaced: `79.79<U+2060>.78.202` becomes the address it displays as."""
    return text if text.isascii() else "".join(ch for ch in text if not is_invisible(ch))


def has_invisible(text: str) -> bool:
    return not text.isascii() and any(is_invisible(ch) for ch in text)
