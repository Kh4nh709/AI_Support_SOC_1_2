"""A local OpenAI-compatible LLM stub for the UI end-to-end stack (P10-T12).

The real `DeepSeekAdapter` (backend/app/llm/adapter.py) talks to this server over HTTP, exactly as it
talks to DeepSeek: `POST {LLM_BASE_URL}/chat/completions`. Nothing in `backend/app` imports test code, no
live model is ever called, and the stack that starts this server unsets every provider key. The answers
are canned, but each one is built from the prompt it answers, so the product's own gate accepts it:

* triage_v2 (proposer): `structured_basis` copied from the `## Alert` facts (gate step 2), one reason whose
  quote is a verbatim line of the `rule_description` block (step 3), verdict `needs_review` (step 4 never
  forces it, and it is the one verdict the pilot's blind arm may not show). The reason's `claim` carries a
  token derived from the alert id (`claim_token`), which the blind spec looks for: it is in no other place.
* verifier_v1: echoes the proposer's own verdict out of the `proposer` block, `agree: true` (step 6 agrees).
* investigate_v2 (Tier 2): two evidence items about the dossier's first alert, one quoted from its raw log
  (verified by the server) and one that is in no log (rejected as `quote_not_found`), so the case page shows
  both marks; the conclusion `false_positive` stands because one item verified.

Stdlib only; binds 127.0.0.1 only. `E2E_STUB_DUMP_DIR`, when set, writes each request's prompts there (the
data is synthetic; this is for developing the stub, the stack never sets it).
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"
DEFAULT_PORT = 18100

_BLOCK_RE = re.compile(
    r'<untrusted_data nonce="(?P<nonce>[^"]+)" source="(?P<source>[a-z_]+)"(?P<attrs>[^>]*)>\n'
    r"(?P<body>.*?)\n</untrusted_data nonce=\"(?P=nonce)\">",
    re.DOTALL,
)
_ATTR_RE = re.compile(r'(\w+)="([^"]*)"')
_SEP = " · "


def claim_token(alert_id: str) -> str:
    """The token this stub puts in the `claim` of a proposer answer for `alert_id`. The Playwright fixtures
    compute the same value (frontend/e2e/fixtures.ts, `claimToken`)."""
    return "stub-claim-" + hashlib.sha1(alert_id.encode("utf-8")).hexdigest()[:10]


def _blocks(user: str) -> list[dict]:
    found = []
    for match in _BLOCK_RE.finditer(user):
        attrs = dict(_ATTR_RE.findall(match.group("attrs")))
        found.append(
            {
                "source": match.group("source"),
                "attrs": attrs,
                "text": html.unescape(match.group("body")),
                "start": match.start(),
            }
        )
    return found


def _alert_facts(user: str) -> dict[str, str]:
    """`name: value` pairs of the `## Alert` section: from its heading to the first block."""
    head = user.find("## Alert")
    if head < 0:
        return {}
    end = user.find("<untrusted_data", head)
    section = user[head : end if end >= 0 else len(user)]
    facts: dict[str, str] = {}
    for line in section.splitlines():
        for part in line.split(_SEP):
            name, sep, value = part.partition(": ")
            if sep and re.fullmatch(r"[a-z_]+", name.strip()):
                facts.setdefault(name.strip(), value.strip())
    return facts


def _first_line(text: str, *, minimum: int = 8, maximum: int = 100) -> str:
    """A quote the gate will find again: one line of the block, whitespace-trimmed, no & < >."""
    for line in text.splitlines():
        line = " ".join(line.split())
        if len(line) >= minimum:
            return line[:maximum].rstrip()
    return " ".join(text.split())[:maximum]


def triage_answer(user: str) -> dict:
    facts = _alert_facts(user)
    alert_id = facts.get("alert_id", "")
    blocks = _blocks(user)
    description = next((b for b in blocks if b["source"] == "rule_description"), None)
    reason_source, reason_text = (
        ("rule_description", description["text"])
        if description is not None
        else ("wazuh_raw_log", next((b["text"] for b in blocks), ""))
    )
    return {
        "suggested_action": "needs_review",
        "confidence": "medium",
        "structured_basis": {
            "severity": facts.get("severity", "low"),
            "ioc_reputation": facts.get("ioc_reputation", "skipped"),
            "asset_criticality": facts.get("asset_criticality", "unknown"),
            "identity_privileged": facts.get("identity_privileged", "unknown"),
            "occurrence_count": int(facts.get("occurrence_count", "1")),
            "playbook_rule_applied": None,
        },
        "reasons": [
            {
                "claim": f"{claim_token(alert_id)} the description names a routine event.",
                "quote": _first_line(reason_text),
                "source": reason_source,
            }
        ],
        "playbook_used": None,
    }


def verifier_answer(user: str) -> dict:
    proposer = next((b for b in _blocks(user) if b["source"] == "proposer"), None)
    verdict = "needs_review"
    if proposer is not None:
        try:
            verdict = json.loads(proposer["text"])["verdict"]
        except (ValueError, KeyError, TypeError):
            pass
    return {
        "agree": True,
        "structured_only_verdict": verdict,
        "reason": "The structured facts alone lead to the same verdict.",
    }


_CLUSTER_RE = re.compile(r"^alert_id: (\d+\.\d+) " + re.escape(_SEP.strip()), re.MULTILINE)


def _cluster_alert_id(user: str, position: int) -> str | None:
    """The alert a `## Clusters` block belongs to: the `alert_id: X · rule_id: ...` line just above it."""
    found = None
    for match in _CLUSTER_RE.finditer(user, 0, position):
        found = match.group(1)
    return found


def investigate_answer(user: str) -> dict:
    """Two evidence items about the dossier's first alert: one quoted from its raw log (the server checks it
    against the log and marks it verified), one that is in no log (marked as not found). The dossier names an
    alert on the line above its blocks, not in a block attribute."""
    evidence = []
    for block in _blocks(user):
        if block["source"] != "wazuh_raw_log":
            continue
        alert_id = _cluster_alert_id(user, block["start"])
        if alert_id is None:
            continue
        evidence.append(
            {
                "alert_id": alert_id,
                "quote": _first_line(block["text"]),
                "why": "This line is what the alert of the case reports.",
            }
        )
        evidence.append(
            {
                "alert_id": alert_id,
                "quote": "a line that no log of this case holds",
                "why": "The assistant cites a line that is not in the case.",
            }
        )
        break
    return {
        "summary": "The case holds one repeated event that looks routine.",
        "attack_narrative": "Nothing in the cluster shows an attacker moving past the first event.",
        "suggested_conclusion": "false_positive",
        "confidence": "medium",
        "gia_thuyet": [
            {
                "noi_dung": "The event is the routine noise of a test host.",
                "evidence_for": ["The description names a routine event."],
                "evidence_against": ["Only the alert text was read; no host was inspected."],
            }
        ],
        "evidence": evidence,
        "next_steps": ["Close the case if the owner of the host confirms the activity."],
        "playbook_used": None,
    }


def answer_for(system: str, user: str) -> dict:
    if "## Schema verifier_v1" in system:
        return verifier_answer(user)
    if "## Schema investigate_v2" in system:
        return investigate_answer(user)
    return triage_answer(user)


_dump_lock = threading.Lock()
_dump_count = 0


def _dump(system: str, user: str, answer: dict) -> None:
    global _dump_count
    directory = os.environ.get("E2E_STUB_DUMP_DIR")
    if not directory:
        return
    with _dump_lock:
        _dump_count += 1
        base = Path(directory) / f"{_dump_count:04d}"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.with_suffix(".txt").write_text(
        f"{system}\n\n=====\n\n{user}\n\n=====\n\n{json.dumps(answer)}\n"
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "e2e-llm-stub"

    def log_message(self, format: str, *args: object) -> None:
        # One line, never a prompt: the request line and the status only.
        sys.stderr.write(
            f"llm-stub: {self.command} {self.path} {args[1] if len(args) > 1 else ''}\n"
        )

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
            messages = request["messages"]
            system = next(m["content"] for m in messages if m["role"] == "system")
            user = next(m["content"] for m in messages if m["role"] == "user")
        except (ValueError, KeyError, StopIteration, TypeError):
            self._send(400, {"error": {"message": "bad request"}})
            return
        answer = answer_for(system, user)
        _dump(system, user, answer)
        content = json.dumps(answer, ensure_ascii=False)
        prompt_tokens = max(1, (len(system) + len(user)) // 3)
        completion_tokens = max(1, len(content) // 3)
        self._send(
            200,
            {
                "id": "e2e-stub-" + hashlib.sha1(f"{time.time_ns()}".encode()).hexdigest()[:12],
                "object": "chat.completion",
                "created": int(time.time()),
                "model": request.get("model", "e2e-stub"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
            },
        )


def main(argv: list[str]) -> int:
    port = int(argv[1]) if len(argv) > 1 else DEFAULT_PORT
    server = ThreadingHTTPServer((HOST, port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
