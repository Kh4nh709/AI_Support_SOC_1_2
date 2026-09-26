#!/usr/bin/env python3
"""Print `export PGHOST=… PGPORT=… PGUSER=… PGPASSWORD=…` for a libpq DSN.

`make test-db` evals this so the tests that build scratch databases with a bare
`createdb <name>` or a `postgresql:///<name>` DSN (test_auth.py, test_pipeline.py,
test_g7_llm_off.py) reach the SAME server and credentials as TEST_DATABASE_URL —
the Docker cluster on 127.0.0.1:55432 since 20/09/2026 — instead of libpq's
default (the local socket, i.e. whatever native cluster happens to be there).
A socket-form DSN (empty host) prints empty values, which libpq treats as unset.

`dsn_env.py --redact <dsn>` prints the DSN with every password in it replaced by
`***` instead: the one redaction routine, used by `make test-db` for the DSN it
shows and by backend/tests/conftest.py for every DSN a test report can show
(DEC-122, DEC-123).
"""
from __future__ import annotations

import re
import shlex
import sys
import urllib.parse

# libpq's key=value form: `password=value` or `password='quoted \' value'`.
_KEYWORD_PASSWORD = re.compile(r"\bpassword\s*=\s*('(?:[^'\\]|\\.)*(?:'|$)|\S*)")
# A URI's query string may carry the password too: postgresql:///db?password=…
_QUERY_PASSWORD = re.compile(r"[?&]password=([^&#]*)")


def _password_spans(dsn: str) -> list[tuple[int, int]]:
    """(start, end) of every password in `dsn`, in order.

    The URI password runs from the first `:` after `scheme://` to the LAST `@`, never to the
    first one: a password may itself contain `@`, `:`, `/`, `?` or `#` (libpq accepts `#` and
    `?` raw), and urllib.parse ends the authority at the first `/`, `?` or `#`, which would
    miss the password entirely and hand the whole DSN back unmasked. Masking to the last `@`
    can only ever hide more than the password, never less.
    """
    scheme_end = dsn.find("://")
    if scheme_end < 0:
        return [m.span(1) for m in _KEYWORD_PASSWORD.finditer(dsn)]
    start = scheme_end + 3
    spans = [m.span(1) for m in _QUERY_PASSWORD.finditer(dsn, start)]
    at = dsn.rfind("@")
    colon = dsn.find(":", start, at) if at >= start else -1
    if colon >= 0:
        spans.append((colon + 1, at))
    return sorted(spans)


def redact(dsn: str) -> str:
    """`dsn` with every password in it replaced by `***` (unchanged when it holds none)."""
    out, last = [], 0
    for start, end in _password_spans(dsn):
        if start < last:  # overlaps the span just masked: widen it, never print a piece
            last = max(last, end)
            continue
        out += [dsn[last:start], "***"]
        last = end
    return "".join(out) + dsn[last:]


def passwords(dsn: str) -> list[str]:
    """Every password in `dsn` as written there: percent-escapes not decoded, a quoted
    key=value password unquoted."""
    found = []
    for start, end in _password_spans(dsn):
        value = dsn[start:end]
        if value.startswith("'"):
            value = re.sub(r"\\(.)", r"\1", value[1:-1] if value.endswith("'") else value[1:])
        if value:
            found.append(value)
    return found


def main(argv: list[str]) -> int:
    redacting = len(argv) > 1 and argv[1] == "--redact"
    if len(argv) != (3 if redacting else 2):
        print("usage: dsn_env.py <dsn>  |  dsn_env.py --redact <dsn>", file=sys.stderr)
        return 2
    if redacting:
        print(redact(argv[2]))
        return 0
    p = urllib.parse.urlsplit(argv[1])
    pairs = {
        "PGHOST": p.hostname or "",
        "PGPORT": str(p.port) if p.port else "",
        "PGUSER": urllib.parse.unquote(p.username or ""),
        "PGPASSWORD": urllib.parse.unquote(p.password or ""),
    }
    print("export " + " ".join(f"{k}={shlex.quote(v)}" for k, v in pairs.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
