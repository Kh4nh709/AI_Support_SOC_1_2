"""Tests for `app.web.handlers` (P5-T01, planning decision 1): the worker's
job-type -> handler table is discovered from this package, exactly as
`app.web.routers` discovers routers — pure tests, no `db` marker, since
discovery never opens a connection.

The failing-case tests (`test_a_module_without_JOB_TYPE_fails_loudly` and the
three after it) exercise the real `iter_handlers()`, not a copy of it: each
points the package's own `__path__` at a `tmp_path` directory holding one or
two hand-written modules, via `monkeypatch.setattr`, then calls
`handlers_pkg.iter_handlers()` unchanged. `sys.modules` is cleaned up after
each so a later test's real discovery never sees a leftover scratch module.
"""

from __future__ import annotations

import sys

import pytest
from app.infra import puller
from app.infra.errors import PermanentError
from app.soar import pipeline
from app.tier1 import triage
from app.web import handlers as handlers_pkg
from app.web.handlers import health as health_handler
from app.web.worker import HANDLERS, TIMEOUTS


def test_iter_handlers_discovers_every_handler_module_on_main():
    # P5-T11: a fourth module (health.py) joins pull/pipeline/triage — the set
    # this asserts grows by one every time a later P5 card adds its own
    # module, exactly as planning decision 1 intends (P5-tasks.md §6.1);
    # this test's job is to track that set, not pin it at three forever.
    result = handlers_pkg.iter_handlers()
    assert set(result) == {"pipeline", "pull", "triage", "health"}
    assert result["pull"] is puller.pull_job
    assert result["pipeline"] is pipeline.run_pipeline_job
    assert result["triage"] is triage.run_triage_job
    assert result["health"] is health_handler.handle


def test_iter_timeouts_is_empty_until_a_module_declares_one():
    assert handlers_pkg.iter_timeouts() == {}


def test_worker_module_exposes_both_mappings():
    assert HANDLERS == handlers_pkg.iter_handlers()
    assert TIMEOUTS == handlers_pkg.iter_timeouts()


def test_main_passes_timeouts_to_run_forever(monkeypatch):
    """Design note 5(c)'s red-step-discriminating assertion: `TIMEOUTS ==
    iter_timeouts()` alone stays green even if `main()` never hands it to
    `run_forever` — so this inspects the actual call, via `monkeypatch` on
    `app.web.worker.run_forever`, rather than the module-level mapping."""
    from app.web import worker as worker_module

    captured: dict[str, object] = {}

    def fake_run_forever(conn_factory, handlers, *, once, timeouts=None):
        captured["handlers"] = handlers
        captured["timeouts"] = timeouts

    class _FakeConn:
        def commit(self) -> None:
            pass

    monkeypatch.setattr(worker_module, "run_forever", fake_run_forever)
    monkeypatch.setattr(worker_module.config, "load", lambda: None)
    monkeypatch.setattr(worker_module.db, "connect", lambda: _FakeConn())
    monkeypatch.setattr(worker_module, "enqueue", lambda conn, job_type, subject_id: None)

    worker_module.main(["--once"])

    assert captured["timeouts"] is worker_module.TIMEOUTS
    assert captured["handlers"] is worker_module.HANDLERS


def _write(tmp_path, name: str, body: str) -> None:
    (tmp_path / f"{name}.py").write_text(body, encoding="utf-8")


def _point_package_at(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(handlers_pkg, "__path__", [str(tmp_path)])


def _forget(*module_names: str) -> None:
    for name in module_names:
        sys.modules.pop(f"app.web.handlers.{name}", None)


def test_a_module_without_JOB_TYPE_fails_loudly(tmp_path, monkeypatch):
    _write(tmp_path, "scratch_no_job_type", "def handle(conn, job):\n    pass\n")
    _point_package_at(monkeypatch, tmp_path)
    try:
        with pytest.raises(AttributeError, match="JOB_TYPE"):
            handlers_pkg.iter_handlers()
    finally:
        _forget("scratch_no_job_type")


def test_a_module_without_handle_fails_loudly(tmp_path, monkeypatch):
    _write(tmp_path, "scratch_no_handle", 'JOB_TYPE = "pull"\n')
    _point_package_at(monkeypatch, tmp_path)
    try:
        with pytest.raises(AttributeError, match="'handle'"):
            handlers_pkg.iter_handlers()
    finally:
        _forget("scratch_no_handle")


def test_duplicate_job_type_is_permanent_error(tmp_path, monkeypatch):
    _write(tmp_path, "scratch_dup_a", 'JOB_TYPE = "pull"\n\n\ndef handle(conn, job):\n    pass\n')
    _write(tmp_path, "scratch_dup_b", 'JOB_TYPE = "pull"\n\n\ndef handle(conn, job):\n    pass\n')
    _point_package_at(monkeypatch, tmp_path)
    try:
        with pytest.raises(PermanentError) as exc_info:
            handlers_pkg.iter_handlers()
        assert "scratch_dup_b" in str(exc_info.value)
    finally:
        _forget("scratch_dup_a", "scratch_dup_b")


def test_unknown_job_type_is_permanent_error(tmp_path, monkeypatch):
    _write(
        tmp_path, "scratch_unknown", 'JOB_TYPE = "bogus"\n\n\ndef handle(conn, job):\n    pass\n'
    )
    _point_package_at(monkeypatch, tmp_path)
    try:
        with pytest.raises(PermanentError) as exc_info:
            handlers_pkg.iter_handlers()
        assert "scratch_unknown" in str(exc_info.value)
        assert "'bogus'" in str(exc_info.value)
    finally:
        _forget("scratch_unknown")


def test_iter_timeouts_maps_a_declared_timeout_by_job_type(tmp_path, monkeypatch):
    # P5-T01 review finding 1: the module name differs from its JOB_TYPE, so a
    # keying by module name would fail; the second module declares no timeout.
    _write(
        tmp_path,
        "scratch_t",
        'JOB_TYPE = "health"\nSTATEMENT_TIMEOUT = "5s"\n\n\ndef handle(conn, job):\n    pass\n',
    )
    _write(tmp_path, "scratch_u", 'JOB_TYPE = "pull"\n\n\ndef handle(conn, job):\n    pass\n')
    _point_package_at(monkeypatch, tmp_path)
    try:
        assert handlers_pkg.iter_timeouts() == {"health": "5s"}
    finally:
        _forget("scratch_t", "scratch_u")
