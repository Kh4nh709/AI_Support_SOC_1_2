#!/usr/bin/env python3
"""A stand-in for n8n's `soar-approval` webhook, so the page "Phản hồi SOAR" can be tried before the n8n side exists.

It answers the call the web makes when a person presses a button (spec 2026-11-16 §3, "Contract B"): a POST with the
header `X-SOAR-Secret` and the JSON body `{"source": "web", "review_id", "decision", "callback", "user", "user_role",
"note", "requested_at"}`. It decides nothing and changes nothing anywhere: it only answers, by the mode it was started in.

    python3 scripts/mock_n8n_approval.py --mode ok         # 200 {"ok": true, "status": kept|undone|false_positive, ...}
    python3 scripts/mock_n8n_approval.py --mode fail       # 200 {"ok": false, ...}: the action failed, the ticket keeps its state
    python3 scripts/mock_n8n_approval.py --mode conflict   # 409 {"ok": false, "status": "undone", ...}: handled elsewhere
    python3 scripts/mock_n8n_approval.py --mode slow       # waits --slow-seconds (default 60), then answers as ok

Standard library only. Options: `--host` (default 127.0.0.1) and `--port` (default 5678; 0 picks a free one). The
`X-SOAR-Secret` it requires is read from the ENVIRONMENT, variable `N8N_APPROVAL_SECRET` (the app's own name for it), never from the
command line, where `ps` and the shell history would show it: `N8N_APPROVAL_SECRET=thu-nghiem python3 scripts/mock_n8n_approval.py`.
Without the variable any secret is accepted; a wrong one is a 401, as the real n8n would answer.

To point the web at it, set in `.env`: `N8N_APPROVAL_URL=http://127.0.0.1:5678/webhook/soar-approval` and
`N8N_APPROVAL_SECRET=<the same secret>`, then recreate the app container (README, "Phản hồi SOAR"). The server prints one
line per request: the time, the decision, the review id, the user and the answer; never the secret. It listens on the
loopback address unless told otherwise: it has no business on a network.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

MODES = ("ok", "fail", "conflict", "slow")
#: What a successful decision comes back as.
STATUS_OF_DECISION = {"keep": "kept", "undo": "undone", "fp": "false_positive"}
#: A body larger than this is not a decision (the real one is a few hundred bytes).
MAX_BODY_BYTES = 64 * 1024


def answer_for(mode: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """`(HTTP status, JSON body)` for a decision `body`, in `mode`. A body naming a decision the web never sends is
    answered like n8n would answer a malformed one: 400."""
    decision = body.get("decision")
    if decision not in STATUS_OF_DECISION:
        return 400, {"ok": False, "message": "decision must be keep, undo or fp"}
    status = STATUS_OF_DECISION[decision]
    who = body.get("user") or "?"
    if mode == "fail":
        return 200, {
            "ok": False,
            "status": "open",
            "result": "mock: simulated failure",
            "message": f"GIẢ LẬP THẤT BẠI: n8n giả lập không thực hiện được '{decision}' (người bấm: {who})",
        }
    if mode == "conflict":
        return 409, {
            "ok": False,
            "status": "undone",
            "message": "GIẢ LẬP: phiếu đã được xử lý ở nơi khác (n8n giả lập)",
        }
    return 200, {
        "ok": True,
        "status": status,
        "result": f"mock: {decision} done",
        "message": f"GIẢ LẬP: đã '{decision}' phiếu {body.get('review_id')} (người bấm: {who})",
    }


def make_handler(mode: str, secret: str, slow_seconds: float) -> type[BaseHTTPRequestHandler]:
    """The request handler class for a server in `mode`. Exposed so a test can run the same code in a thread."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "mock-n8n-approval"

        def log_message(self, format: str, *args: Any) -> None:
            pass  # one line per decision is printed below; the default per-request line carries nothing more

        def _send(self, code: int, body: dict[str, Any]) -> None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            self._send(200, {"mock": True, "mode": mode})

        def do_POST(self) -> None:
            given = self.headers.get("X-SOAR-Secret", "")
            if secret and not hmac.compare_digest(given.encode(), secret.encode()):
                print(f"{_now()} 401 wrong or missing X-SOAR-Secret", flush=True)
                self._send(401, {"ok": False, "message": "unauthorized"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY_BYTES:
                self._send(413, {"ok": False, "message": "body too large"})
                return
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                body = None
            if not isinstance(body, dict):
                print(f"{_now()} 400 the body is not a JSON object", flush=True)
                self._send(400, {"ok": False, "message": "the body must be a JSON object"})
                return
            if mode == "slow":
                time.sleep(slow_seconds)
            code, answer = answer_for(mode, body)
            print(
                f"{_now()} {code} decision={body.get('decision')} review={body.get('review_id')} "
                f"user={body.get('user')} role={body.get('user_role')} -> ok={answer.get('ok')} "
                f"status={answer.get('status')}",
                flush=True,
            )
            self._send(code, answer)

    return Handler


def _now() -> str:
    return time.strftime("%H:%M:%S")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A stand-in for n8n's soar-approval webhook (it answers; it changes nothing)."
    )
    parser.add_argument("--mode", choices=MODES, default="ok", help="how it answers (default ok)")
    parser.add_argument(
        "--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=5678, help="port (default 5678; 0 = any free one)"
    )
    parser.add_argument(
        "--slow-seconds", type=float, default=60.0, help="how long --mode slow waits (default 60)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    secret = os.environ.get("N8N_APPROVAL_SECRET", "")
    server = ThreadingHTTPServer(
        (args.host, args.port), make_handler(args.mode, secret, args.slow_seconds)
    )
    host, port = server.server_address[:2]
    print(
        f"mock n8n approval: mode={args.mode} listening on http://{host}:{port}/webhook/soar-approval "
        f"(secret {'required' if secret else 'not required'}, from N8N_APPROVAL_SECRET); Ctrl+C to stop",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
