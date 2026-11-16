"""SR-T3 — `scripts/ui_e2e_n8n.py`, the stand-in for n8n's soar-approval webhook that the e2e stack runs.

It is `scripts/mock_n8n_approval.py` with its mode read from a file at every request (so a spec can make a press fail), and it
must never answer without a secret to check: the stand-in accepts ANY request when its secret is empty, and the e2e stack's whole
point is that the web sends the secret it was configured with. So it refuses to start without one, naming the variable and
never a value. Pure in the sense of `make test`: no database, no network beyond 127.0.0.1 (an OS-chosen port).
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest
from app.infra import n8n_approval
from app.infra.config import Config

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ui_e2e_n8n.py"
SECRET = "e2e-secret-0123456789"


def _load_script():
    # the script puts its own directory on the path to import the stand-in it wraps, as when it runs
    spec = importlib.util.spec_from_file_location("ui_e2e_n8n", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wrapper = _load_script()


def _run(env_extra: dict[str, str], *args: str) -> subprocess.CompletedProcess:
    """The script as the stack runs it, with a clean environment of only what is given. A start that is refused returns at once;
    one that is not would serve for ever, which the timeout turns into a failure of the test."""
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1", **env_extra}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )


@contextmanager
def _serving(mode_file: Path, secret: str = SECRET) -> Iterator[str]:
    server = wrapper.make_server(0, secret, str(mode_file))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/webhook/soar-approval"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _ask(url: str, decision: str = "undo", *, secret: str = SECRET):
    cfg = replace(
        Config(), N8N_APPROVAL_URL=url, N8N_APPROVAL_SECRET=secret, N8N_APPROVAL_TIMEOUT_SECONDS=5
    )
    return n8n_approval.call(
        cfg, review_id="K7QM2XHP", decision=decision, user="e2e-t2", user_role="tier2", note=None
    )


# ── it refuses to start without a secret ────────────────────────────────────────────────────


@pytest.mark.parametrize("given", [{}, {"N8N_APPROVAL_SECRET": ""}, {"N8N_APPROVAL_SECRET": "   "}])
def test_it_refuses_to_start_without_a_secret_and_names_the_variable(given, tmp_path):
    mode_file = tmp_path / "n8n.mode"
    done = _run({"E2E_N8N_MODE_FILE": str(mode_file), **given}, "0")
    assert done.returncode != 0
    assert "N8N_APPROVAL_SECRET" in done.stderr
    # the message names the variable and nothing it could hold
    assert "e2e-secret" not in done.stderr + done.stdout


def test_it_refuses_to_start_without_the_mode_file_variable():
    done = _run({"N8N_APPROVAL_SECRET": SECRET}, "0")
    assert done.returncode != 0
    assert "E2E_N8N_MODE_FILE" in done.stderr
    assert SECRET not in done.stderr + done.stdout


def test_it_refuses_a_port_that_is_not_a_number():
    done = _run({"N8N_APPROVAL_SECRET": SECRET, "E2E_N8N_MODE_FILE": "x"}, "not-a-port")
    assert done.returncode != 0


def test_a_server_cannot_even_be_made_without_a_secret(tmp_path):
    for empty in ("", "  "):
        with pytest.raises(ValueError, match="N8N_APPROVAL_SECRET"):
            wrapper.make_server(0, empty, str(tmp_path / "n8n.mode"))


# ── the mode comes from the file, at every request ──────────────────────────────────────────


def test_the_mode_file_decides_each_answer_and_can_change_between_two_presses(tmp_path):
    mode_file = tmp_path / "n8n.mode"
    mode_file.write_text("ok\n")
    with _serving(mode_file) as url:
        first = _ask(url)
        assert (first.outcome, first.status) == ("ok", "undone")
        mode_file.write_text("fail\n")
        failed = _ask(url)
        assert failed.outcome == "failed" and "GIẢ LẬP THẤT BẠI" in (failed.message or "")
        mode_file.write_text("conflict\n")
        conflict = _ask(url)
        assert (conflict.outcome, conflict.status) == ("conflict", "undone")
        mode_file.write_text("ok\n")
        assert _ask(url).outcome == "ok"


def test_no_file_or_a_file_that_names_no_mode_is_ok(tmp_path):
    mode_file = tmp_path / "n8n.mode"
    with _serving(mode_file) as url:  # the file does not exist
        assert _ask(url).outcome == "ok"
        for odd in ("", "nonsense", "FAIL ", "../etc/passwd", "ok fail"):
            mode_file.write_text(odd)
            assert _ask(url).outcome == "ok", odd


def test_the_secret_is_still_checked(tmp_path):
    mode_file = tmp_path / "n8n.mode"
    mode_file.write_text("ok\n")
    with _serving(mode_file) as url:
        wrong = _ask(url, secret="a-different-secret")
        assert (
            wrong.outcome == "unavailable"
        )  # the 401 of the stand-in, which the client calls unavailable
        assert _ask(url).outcome == "ok"


def test_it_listens_on_the_loopback_address_only():
    assert wrapper.HOST == "127.0.0.1"
