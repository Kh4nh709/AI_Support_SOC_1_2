"""`infra.storable` — the one definition of "text the database and the HTTP client can carry" (SR-T1, fix round 1).

Two things make a Python `str` unusable even though it is a valid `str`:

* a NUL character (`"\\x00"`): PostgreSQL refuses it in `text` and in `jsonb`;
* a lone UTF-16 surrogate (`"\\ud800"` to `"\\udfff"` not part of a pair): `json.loads` accepts the escape and hands it over, but
  `str.encode("utf-8")` raises on it, so neither psycopg nor httpx can send it. A JavaScript string cut inside an emoji produces exactly
  this, and n8n is JavaScript.

Text that comes from outside (what n8n pushes, what n8n answers, what a person types) must go through here before a write that cannot
be undone: `is_storable` to REFUSE it (the webhook's body, the decision's note: a `400` or a `422`), `make_storable` to CLEAN it (n8n's
answer, which has already been acted on and must still be recorded). Nothing else in the code names these characters.
"""

from __future__ import annotations

REPLACEMENT = "�"


def is_storable(text: str) -> bool:
    """True when `text` holds no NUL and can be encoded as UTF-8 (no lone surrogate)."""
    if "\x00" in text:
        return False
    if text.isascii():
        return True
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def make_storable(text: str) -> str:
    """`text` with every NUL removed and every lone surrogate replaced by U+FFFD; a text that is already storable is returned as
    it is. A valid pair is one character in a Python `str` and is never touched."""
    if is_storable(text):
        return text
    text = text.replace("\x00", "")
    return "".join(REPLACEMENT if "\ud800" <= char <= "\udfff" else char for char in text)
