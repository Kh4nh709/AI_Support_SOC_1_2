"""The one definition of an alert id's exact shape (DEC-209, DEC-211 R6 item A).

It lives in `infra` because `infra` imports nothing from the app (G1, context pack §4) and every
package that needs the shape may import `infra`: `llm.builder` (`ID_PATTERNS["alert_id"]` is this very
object, so ① renders an id only in this shape), `security.linter` (the one out-of-block token it
passes as an id) and `infra.intake` (the webhook refuses any other id, with the reason `id`). Three
readers of one object cannot drift apart; `test_alert_id_source.py` pins that they are one object.

Exact on purpose. Two shapes, no more:

* the Wazuh id `<epoch>.<n>`: ASCII digits, a dot, ASCII digits;
* the SOAR (Graylog) id `gl-<event ULID>-<message UUID>`: a Crockford base32 ULID (26 characters,
  upper case, no I, L, O or U) and a lower-case UUID.

ASCII on purpose (INT-T02 review, F1). `\\d` in a `str` pattern takes every Unicode decimal digit, so
without `re.ASCII` an id written in mathematical-bold, fullwidth or Arabic-Indic digits matched, was
stored as a different alert from the real one it looks like (no 409), and passed the linter. The flag
narrows the builder, the linter and the webhook together, because they are one object; real ids reach ①
only through the webhook and the puller, and both carry ASCII.

The linter passes any token outside an untrusted block that fits an id pattern, so a looser second
shape would let free text that merely looks like an id reach the model. That is why the n8n test
generator's `gl-TEST-<rule>-<epoch ms>` is not accepted and why the webhook is not widened to take it
(the SOAR side gives its test scenarios real ids instead).
"""

from __future__ import annotations

import re

ALERT_ID_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:\d+\.\d+|gl-[0-9A-HJKMNP-TV-Z]{26}"
    r"-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.ASCII,
)


def is_alert_id(value: object) -> bool:
    """Whether `value` is a string that matches `ALERT_ID_PATTERN` as a whole (`fullmatch`: a
    trailing newline, which `$` alone would let through, is a mismatch). Anything that is not a
    `str` (a number, a list, an object, `None`) is not an alert id, and is never matched against
    the pattern, which would raise on it."""
    return isinstance(value, str) and ALERT_ID_PATTERN.fullmatch(value) is not None
