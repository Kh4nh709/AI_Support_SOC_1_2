"""SR-T1 — `scripts/mock_n8n_approval.py`, the stand-in for n8n's soar-approval webhook.

The Owner tries the page "Phản hồi SOAR" against it before the n8n side exists, so the stand-in is held to the same
client the app uses (`app.infra.n8n_approval`): the real HTTP client talks to the real stand-in over the loopback address
(an OS-chosen port, nothing outside the machine), once per mode. Pure in the sense of `make test`: no database, no
network beyond 127.0.0.1.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from app.infra import n8n_approval
from app.infra.config import Config

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "mock_n8n_approval.py"
SECRET = "mock-secret-123"


def _load_script():
    spec = importlib.util.spec_from_file_location("mock_n8n_approval", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mock = _load_script()


@contextmanager
def _serving(mode: str, secret: str = SECRET, slow_seconds: float = 0.0) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), mock.make_handler(mode, secret, slow_seconds))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/webhook/soar-approval"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _ask(url: str, decision: str = "undo", *, secret: str = SECRET, timeout: int = 5):
    cfg = replace(
        Config(),
        N8N_APPROVAL_URL=url,
        N8N_APPROVAL_SECRET=secret,
        N8N_APPROVAL_TIMEOUT_SECONDS=timeout,
    )
    return n8n_approval.call(
        cfg, review_id="K7QM2XHP", decision=decision, user="alice", user_role="tier2", note="x"
    )


@pytest.mark.parametrize(
    "decision,status", [("keep", "kept"), ("undo", "undone"), ("fp", "false_positive")]
)
def test_ok_mode_answers_the_status_the_decision_means(decision, status):
    with _serving("ok") as url:
        answer = _ask(url, decision)
    assert (answer.outcome, answer.status) == ("ok", status)
    assert answer.message and "K7QM2XHP" in answer.message
    assert answer.result


def test_fail_mode_is_a_200_with_ok_false_and_a_message_for_the_person():
    with _serving("fail") as url:
        answer = _ask(url)
    assert answer.outcome == "failed"
    assert answer.message and "THẤT BẠI" in answer.message
    assert answer.http_status == 200


def test_conflict_mode_is_a_409_with_the_status_handled_elsewhere():
    with _serving("conflict") as url:
        answer = _ask(url)
    assert (answer.outcome, answer.status, answer.http_status) == ("conflict", "undone", 409)
    assert answer.message


def test_slow_mode_outlasts_the_clients_timeout_and_is_unavailable():
    with _serving("slow", slow_seconds=4.0) as url:
        answer = _ask(url, timeout=1)
    assert (answer.outcome, answer.kind) == ("unavailable", "timeout")


def test_slow_mode_answers_as_ok_when_it_is_waited_for():
    with _serving("slow", slow_seconds=0.2) as url:
        answer = _ask(url, timeout=5)
    assert answer.outcome == "ok"


def test_a_wrong_secret_is_a_401_which_the_client_calls_unavailable():
    with _serving("ok") as url:
        answer = _ask(url, secret="not-the-secret")
    assert (answer.outcome, answer.kind, answer.http_status) == ("unavailable", "http", 401)


def test_without_a_required_secret_any_secret_is_accepted():
    with _serving("ok", secret="") as url:
        assert _ask(url, secret="anything").outcome == "ok"


def test_a_body_that_is_not_a_decision_is_a_400():
    assert mock.answer_for("ok", {"decision": "delete"})[0] == 400
    assert mock.answer_for("ok", {})[0] == 400


def test_the_modes_are_the_four_the_card_names():
    assert mock.MODES == ("ok", "fail", "conflict", "slow")


def test_it_runs_as_a_script_prints_where_it_listens_and_answers_a_call():
    """The way the Owner starts it: `python3 scripts/mock_n8n_approval.py --mode ok`, standard library only."""
    process = subprocess.Popen(
        [sys.executable, "-I", str(SCRIPT), "--port", "0", "--mode", "ok", "--secret", SECRET],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        first = process.stdout.readline()
        match = re.search(r"listening on (http://127\.0\.0\.1:\d+/webhook/soar-approval)", first)
        assert match, first
        assert SECRET not in first
        answer = _ask(match.group(1), "keep")
        assert (answer.outcome, answer.status) == ("ok", "kept")
        line = process.stdout.readline()
        assert "decision=keep" in line and "review=K7QM2XHP" in line and "user=alice" in line
        assert SECRET not in line
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_the_script_imports_nothing_but_the_standard_library():
    text = SCRIPT.read_text(encoding="utf-8")
    imports = set(re.findall(r"(?m)^(?:from|import) ([a-z_]+)", text))
    assert imports <= set(sys.stdlib_module_names) | {"__future__"}, imports
