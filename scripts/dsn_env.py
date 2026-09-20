#!/usr/bin/env python3
"""Print `export PGHOST=… PGPORT=… PGUSER=… PGPASSWORD=…` for a libpq DSN.

`make test-db` evals this so the tests that build scratch databases with a bare
`createdb <name>` or a `postgresql:///<name>` DSN (test_auth.py, test_pipeline.py,
test_g7_llm_off.py) reach the SAME server and credentials as TEST_DATABASE_URL —
the Docker cluster on 127.0.0.1:55432 since 20/09/2026 — instead of libpq's
default (the local socket, i.e. whatever native cluster happens to be there).
A socket-form DSN (empty host) prints empty values, which libpq treats as unset.
"""
from __future__ import annotations

import shlex
import sys
import urllib.parse


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: dsn_env.py <dsn>", file=sys.stderr)
        return 2
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
