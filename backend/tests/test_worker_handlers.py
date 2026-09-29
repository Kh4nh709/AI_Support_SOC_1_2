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
from app.tier1 import digest, triage
from app.tier2 import investigate
from app.web import handlers as handlers_pkg
from app.web.handlers import health as health_handler
from app.web.worker import HANDLERS, TIMEOUTS


def test_iter_handlers_discovers_every_handler_module():
    # Grows by one every time a later P5 card adds its own module, exactly as
    # planning decision 1 intends (P5-tasks.md §6.1) — this test's job is to
    # track that set, not pin it at any fixed count forever. P5-T01's three
    # (pull/pipeline/triage) plus P5-T08's `digest` plus P5-T11's `health`
    # plus P5-T04's `investigate`, the sixth module.
    result = handlers_pkg.iter_handlers()
    assert set(result) == {"digest", "health", "investigate", "pipeline", "pull", "triage"}
    assert result["pull"] is puller.pull_job
    assert result["pipeline"] is pipeline.run_pipeline_job
    assert result["triage"] is triage.run_triage_job
    assert result["digest"] is digest.run_digest_job
    assert result["health"] is health_handler.handle
    assert result["investigate"] is investigate.run_investigate_job


def test_iter_timeouts_reflects_the_declared_timeouts():
    # P5-T04: renamed from "is_empty_until_a_module_declares_one" (P5-T01's own name)
    # now that one has — `investigate` is the first module to declare a
    # STATEMENT_TIMEOUT, exactly the case P5-T01's review round 1 (finding 1)
    # anticipated when it added test_iter_timeouts_maps_a_declared_timeout_by_job_type
    # on a scratch package below. This test's job is unchanged: it still pins the
    # *real* package's total `iter_timeouts()` result; only what that result now is
    # has changed, the same kind of update test_iter_handlers_discovers_every_
    # handler_module above already received once, from P5-T08.
    assert handlers_pkg.iter_timeouts() == {"investigate": "5s"}


def test_worker_module_exposes_both_mappings():
    assert HANDLERS == handlers_pkg.iter_handlers()
    assert TIMEOUTS == handlers_pkg.iter_timeouts()


def test_main_passes_timeouts_to_run_forever(monkeypatch):
    """Design note 5(c)'s red-step-discriminating assertion: `TIMEOUTS ==
    iter_timeouts()` alone stays green even if `main()` never hands it to
    `run_forever` — so this inspects the actual call, via `monkeypatch` on
    `app.web.worker.run_forever`, rather than the module-level mapping.

    P5-T11 review round 1, seeding: also captures every `enqueue(...)` call
    `main()` makes before it starts the loop — `health`'s "system" seed joins
    `pull`'s "indexer" one line down, both idempotent through the same
    partial unique index, so a restart re-arms a dead `health` chain exactly
    as it already does for `pull`.

    P5-T08 review round 1 · A2: also asserts `digest.ensure_scheduled` is
    called exactly once, with `main`'s own connection — the Director lifted
    the "no diff in worker.py" rule for this one line (both cards), so a fake
    stands in for the tier function itself rather than for anything shared."""
    from app.web import worker as worker_module

    captured: dict[str, object] = {}
    enqueued: list[tuple[str, str]] = []

    def fake_run_forever(conn_factory, handlers, *, once, timeouts=None):
        captured["handlers"] = handlers
        captured["timeouts"] = timeouts

    class _FakeConn:
        def commit(self) -> None:
            pass

    fake_conn = _FakeConn()

    def fake_enqueue(conn, job_type, subject_id):
        enqueued.append((job_type, subject_id))

    def fake_ensure_scheduled(conn):
        captured.setdefault("ensure_scheduled_calls", []).append(conn)

    monkeypatch.setattr(worker_module, "run_forever", fake_run_forever)
    monkeypatch.setattr(worker_module.config, "load", lambda: None)
    monkeypatch.setattr(worker_module.db, "connect", lambda: fake_conn)
    monkeypatch.setattr(worker_module, "enqueue", fake_enqueue)
    monkeypatch.setattr(worker_module.digest, "ensure_scheduled", fake_ensure_scheduled)

    worker_module.main(["--once"])

    assert captured["timeouts"] is worker_module.TIMEOUTS
    assert captured["handlers"] is worker_module.HANDLERS
    assert enqueued == [("pull", "indexer"), ("health", "system")]
    assert captured["ensure_scheduled_calls"] == [fake_conn]


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


@pytest.mark.parametrize(
    "value",
    [
        "5",
        "5 s",
        "5seconds",
        "-5s",
        "5.5s",
        "5ms ",
        "PT5S",
        "",
        # N10 (P5-T04 review round 1): a non-string is a `PermanentError` naming the module
        # and the value, not a bare `TypeError` out of `re.fullmatch` ...
        5,
        5.0,
        b"5s",
        # ... and zero, in any unit or spelling, is "no timeout" to Postgres — the handler
        # that declares it has not asked for a limit at all.
        "0s",
        "0",
        "0ms",
        "0min",
        "00s",
    ],
)
def test_iter_timeouts_rejects_a_malformed_statement_timeout(tmp_path, monkeypatch, value):
    # P5-T04: the P5-T01 review's deferred nit ("nothing pinned a declared
    # STATEMENT_TIMEOUT") — validated against the Postgres duration form
    # (^\d+(ms|s|min)$) at discovery time, so a typo fails loudly here rather than as
    # a `SET LOCAL statement_timeout = '...'` syntax error the first time the job runs.
    _write(
        tmp_path,
        "scratch_bad_timeout",
        f'JOB_TYPE = "health"\nSTATEMENT_TIMEOUT = {value!r}\n\n\ndef handle(conn, job):\n    pass\n',
    )
    _point_package_at(monkeypatch, tmp_path)
    try:
        with pytest.raises(PermanentError) as exc_info:
            handlers_pkg.iter_timeouts()
        assert "scratch_bad_timeout" in str(exc_info.value)
        assert "STATEMENT_TIMEOUT" in str(exc_info.value)
    finally:
        _forget("scratch_bad_timeout")


@pytest.mark.parametrize("value", ["5s", "250ms", "3min", "1ms", "10s"])
def test_iter_timeouts_accepts_every_postgres_duration_form(tmp_path, monkeypatch, value):
    _write(
        tmp_path,
        "scratch_good_timeout",
        f'JOB_TYPE = "health"\nSTATEMENT_TIMEOUT = {value!r}\n\n\ndef handle(conn, job):\n    pass\n',
    )
    _point_package_at(monkeypatch, tmp_path)
    try:
        assert handlers_pkg.iter_timeouts() == {"health": value}
    finally:
        _forget("scratch_good_timeout")
