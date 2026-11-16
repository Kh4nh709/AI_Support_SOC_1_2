#!/usr/bin/env python3
"""The stand-in for n8n's `soar-approval` webhook that the e2e stack runs (SR-T3): `scripts/mock_n8n_approval.py`, with its mode
taken from a file at EVERY request.

    ui_e2e_n8n.py PORT        (environment: N8N_APPROVAL_SECRET, E2E_N8N_MODE_FILE)

The stand-in of `mock_n8n_approval.py` answers by the mode it was started in, and the stack's app has one fixed URL for it. A spec
that wants to see a press fail needs the answer to change between two presses, so this wrapper keeps the four handlers of the
stand-in (`ok`, `fail`, `conflict`, `slow`: the real code, imported, not copied) and hands each POST to the one the file names. The
file is in the stack's mode-700 state directory; a spec writes `ok`, `fail`, `conflict` or `slow` into it. Anything else in it, or
no file, is `ok`. It decides nothing and changes nothing anywhere: it only answers. Loopback only; the secret comes from the
environment, never from an argument; it is never printed (the stand-in prints one line per request without it). Without a secret it
refuses to start (exit 2, naming `N8N_APPROVAL_SECRET`), as it does without the mode file: with an empty one the stand-in would
accept any request, and the stack would no longer prove that the web sends its secret.
"""

from __future__ import annotations

import os
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mock_n8n_approval as stand_in  # noqa: E402  (the path is set on the line above)

#: How long the `slow` mode waits, in seconds: long enough to be seen as slow, short enough for a test.
SLOW_SECONDS = 3.0
HOST = "127.0.0.1"


def current_mode(mode_file: str) -> str:
    """The mode the file names; `ok` when there is no file, or it holds something that is not a mode."""
    try:
        mode = Path(mode_file).read_text(encoding="utf-8").strip()
    except OSError:
        return "ok"
    return mode if mode in stand_in.MODES else "ok"


def make_server(port: int, secret: str, mode_file: str) -> ThreadingHTTPServer:
    # `mock_n8n_approval.py` accepts ANY request when its secret is empty. The e2e stack proves that the web sends the secret it
    # was given, so a stand-in with nothing to check would let a web that sent none pass: it is never made without one.
    if not secret.strip():
        raise ValueError("N8N_APPROVAL_SECRET is empty: the stand-in would accept any request")
    handlers = {mode: stand_in.make_handler(mode, secret, SLOW_SECONDS) for mode in stand_in.MODES}

    class Switching(handlers["ok"]):  # type: ignore[misc]  # a class made at run time
        def do_POST(self) -> None:
            handlers[current_mode(mode_file)].do_POST(self)

    return ThreadingHTTPServer((HOST, port), Switching)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not argv[1].isdigit():
        print("usage: ui_e2e_n8n.py PORT", file=sys.stderr)
        return 2
    mode_file = os.environ.get("E2E_N8N_MODE_FILE", "")
    if not mode_file:
        print("ui_e2e_n8n: E2E_N8N_MODE_FILE is not set", file=sys.stderr)
        return 2
    secret = os.environ.get("N8N_APPROVAL_SECRET", "")
    if not secret.strip():
        # the variable is named; its value never is
        print("ui_e2e_n8n: N8N_APPROVAL_SECRET is not set or empty", file=sys.stderr)
        return 2
    server = make_server(int(argv[1]), secret, mode_file)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
