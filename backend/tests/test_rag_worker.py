"""P13-T03 / DEC-210, spec §7.1 — the `rag-worker`: its own handler package and its entry point.

`rag-worker` claims `rag_lookup` and `knowledge_draft` and nothing else; the main worker claims
neither. Their handlers therefore live in `web/rag_handlers/`, not in `web/handlers/`, which the main
worker mounts whole. The discovery contract is `web.handlers`'s own (`JOB_TYPE`, `handle`, optional
`STATEMENT_TIMEOUT`, fail-fast on a mistake); `web.rag_worker.main` runs the same `run_forever` with
those handlers only and seeds no job.

The RAG handlers are `rag_lookup` (P13-T03) and `knowledge_draft` (P13-T04).

Pure tests, no database: discovery never opens a connection.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from app.infra.config import Config
from app.infra.errors import PermanentError
from app.infra.jobs import JOB_TYPES
from app.rag import draft, lookup
from app.web import handlers as main_handlers
from app.web import rag_handlers, rag_worker
from app.web import worker as main_worker
from app.web.rag_handlers import draft as draft_handler
from app.web.rag_handlers import lookup as lookup_handler

#: What `rag_handlers.iter_handlers()` holds.
EXPECTED_TYPES = {"rag_lookup", "knowledge_draft"}
RAG_JOB_TYPES = {"rag_lookup", "knowledge_draft"}


# ── the table ─────────────────────────────────────────────────────────────────────────────────


def test_the_rag_handlers_are_the_ones_discovered_in_their_own_package() -> None:
    found = rag_handlers.iter_handlers()
    assert set(found) == EXPECTED_TYPES
    assert found["rag_lookup"] is lookup.run_lookup_job  # not wrapped: tests patch its `adapter`
    assert EXPECTED_TYPES <= RAG_JOB_TYPES <= JOB_TYPES


def test_the_lookup_handler_module_follows_the_contract() -> None:
    assert lookup_handler.JOB_TYPE == "rag_lookup"
    assert lookup_handler.handle is lookup.run_lookup_job


def test_the_draft_handler_module_follows_the_contract() -> None:
    assert draft_handler.JOB_TYPE == "knowledge_draft"
    assert draft_handler.handle is draft.run_draft_job  # not wrapped: tests pass its `adapter`
    assert rag_handlers.iter_handlers()["knowledge_draft"] is draft.run_draft_job


def test_the_lookup_declares_a_statement_timeout_for_its_searches() -> None:
    timeouts = rag_handlers.iter_timeouts()
    assert timeouts["rag_lookup"] == "10s"
    assert set(timeouts) <= set(rag_handlers.iter_handlers())


def test_the_draft_declares_a_statement_timeout_for_its_candidate_search() -> None:
    assert rag_handlers.iter_timeouts()["knowledge_draft"] == "10s"


def test_the_main_worker_claims_neither_rag_job_type() -> None:
    assert RAG_JOB_TYPES.isdisjoint(main_handlers.iter_handlers())
    assert RAG_JOB_TYPES.isdisjoint(main_handlers.iter_timeouts())
    assert RAG_JOB_TYPES.isdisjoint(main_worker.HANDLERS)
    assert RAG_JOB_TYPES.isdisjoint(main_worker.TIMEOUTS)


def test_the_rag_worker_claims_none_of_the_main_workers_job_types() -> None:
    assert set(rag_handlers.iter_handlers()).isdisjoint(main_handlers.iter_handlers())
    assert set(rag_worker.HANDLERS).isdisjoint(main_worker.HANDLERS)


def test_the_rag_handler_files_are_not_under_the_main_workers_package() -> None:
    main_dir = Path(main_handlers.__file__).parent
    rag_dir = Path(rag_handlers.__file__).parent
    assert main_dir != rag_dir and rag_dir.name == "rag_handlers"
    for name in ("lookup.py", "draft.py"):
        assert not (main_dir / name).exists()
        assert (rag_dir / name).is_file()


def test_the_worker_module_exposes_both_mappings() -> None:
    assert rag_worker.HANDLERS == rag_handlers.iter_handlers()
    assert rag_worker.TIMEOUTS == rag_handlers.iter_timeouts()


# ── main ──────────────────────────────────────────────────────────────────────────────────────


class Conn:
    """A connection that fails the test if anything is asked of it: `main` seeds nothing."""

    def __getattr__(self, name):
        raise AssertionError(f"rag_worker.main touched the connection: {name}")


def run_main(monkeypatch, argv: list[str]) -> dict:
    seen: dict = {"order": []}
    conn = Conn()

    def fake_load():
        seen["order"].append("config")
        return Config()

    def fake_connect():
        seen["order"].append("connect")
        return conn

    def fake_run_forever(conn_factory, handlers, **kwargs):
        seen["order"].append("run")
        seen.update(handlers=handlers, kwargs=kwargs, conn=conn_factory())

    monkeypatch.setattr(rag_worker.config, "load", fake_load)
    monkeypatch.setattr(rag_worker.db, "connect", fake_connect)
    monkeypatch.setattr(rag_worker, "run_forever", fake_run_forever)
    rag_worker.main(argv)
    seen["expected_conn"] = conn
    return seen


def test_main_runs_the_loop_with_the_rag_handlers_only(monkeypatch) -> None:
    seen = run_main(monkeypatch, [])
    assert seen["handlers"] == rag_handlers.iter_handlers()
    assert set(seen["handlers"]) == EXPECTED_TYPES
    assert seen["kwargs"] == {
        "once": False,
        "timeouts": rag_handlers.iter_timeouts(),
        "claim_order": [["rag_lookup"], ["knowledge_draft"]],
    }
    assert seen["conn"] is seen["expected_conn"]


def test_the_rag_worker_claims_every_lookup_before_any_draft() -> None:
    """P13 fix wave, item 21 (Minor 1): `claim_job` takes the oldest due job, and a lookup is on every
    alert while a draft is only on a conclusion, so lookups queued behind drafts arrive after ① has run.
    """
    assert rag_worker.CLAIM_ORDER == [["rag_lookup"], ["knowledge_draft"]]
    assert {t for group in rag_worker.CLAIM_ORDER for t in group} == set(rag_worker.HANDLERS)


def test_main_once_runs_one_cycle(monkeypatch) -> None:
    assert run_main(monkeypatch, ["--once"])["kwargs"]["once"] is True


def test_main_checks_the_environment_before_it_connects_and_seeds_nothing(monkeypatch) -> None:
    seen = run_main(monkeypatch, ["--once"])
    assert seen["order"] == ["config", "connect", "run"]
    # `Conn` raised on any attribute: no `execute`, no `commit`, so no job was enqueued
    for name in ("enqueue", "digest", "ensure_scheduled", "puller"):
        assert not hasattr(rag_worker, name), f"rag_worker.{name}: the entry point seeds nothing"


# ── discovery: the same fail-fast contract as `web.handlers` ──────────────────────────────────


def write(tmp_path: Path, name: str, body: str) -> None:
    (tmp_path / f"{name}.py").write_text(body, encoding="utf-8")


@pytest.fixture
def scratch_package(tmp_path, monkeypatch):
    """Point the package's own `__path__` at a directory of hand-written modules, and forget the
    modules afterwards so a later discovery never sees one."""
    monkeypatch.setattr(rag_handlers, "__path__", [str(tmp_path)])
    yield tmp_path
    for name in [n for n in sys.modules if n.startswith(f"{rag_handlers.__name__}.scratch_")]:
        del sys.modules[name]


def test_a_module_without_job_type_fails_loudly(scratch_package) -> None:
    write(scratch_package, "scratch_no_job_type", "def handle(conn, job):\n    pass\n")
    with pytest.raises(AttributeError, match="JOB_TYPE"):
        rag_handlers.iter_handlers()


def test_a_module_without_handle_fails_loudly(scratch_package) -> None:
    write(scratch_package, "scratch_no_handle", 'JOB_TYPE = "rag_lookup"\n')
    with pytest.raises(AttributeError, match="handle"):
        rag_handlers.iter_handlers()


def test_a_job_type_that_does_not_exist_is_permanent(scratch_package) -> None:
    write(scratch_package, "scratch_unknown", 'JOB_TYPE = "bogus"\ndef handle(c, j):\n    pass\n')
    with pytest.raises(PermanentError, match="bogus"):
        rag_handlers.iter_handlers()


def test_two_modules_claiming_one_job_type_are_permanent(scratch_package) -> None:
    body = 'JOB_TYPE = "rag_lookup"\ndef handle(c, j):\n    pass\n'
    write(scratch_package, "scratch_a", body)
    write(scratch_package, "scratch_b", body)
    with pytest.raises(PermanentError, match="already claimed"):
        rag_handlers.iter_handlers()


def test_a_declared_timeout_is_mapped_by_job_type(scratch_package) -> None:
    body = 'JOB_TYPE = "rag_lookup"\nSTATEMENT_TIMEOUT = "7s"\ndef handle(c, j):\n    pass\n'
    write(scratch_package, "scratch_t", body)
    write(
        scratch_package, "scratch_u", 'JOB_TYPE = "knowledge_draft"\ndef handle(c, j):\n    pass\n'
    )
    assert rag_handlers.iter_timeouts() == {"rag_lookup": "7s"}


@pytest.mark.parametrize("value", ["5", "5 s", "s", "5m", "0s", "0ms", "-1s", "1.5s", "5S", "''"])
def test_a_malformed_or_zero_timeout_is_permanent(scratch_package, value) -> None:
    literal = value if value == "''" else f'"{value}"'
    write(
        scratch_package,
        "scratch_bad",
        f'JOB_TYPE = "rag_lookup"\nSTATEMENT_TIMEOUT = {literal}\ndef handle(c, j):\n    pass\n',
    )
    with pytest.raises(PermanentError, match="STATEMENT_TIMEOUT"):
        rag_handlers.iter_timeouts()


@pytest.mark.parametrize("value", ["250ms", "5s", "3min"])
def test_every_postgres_duration_form_is_accepted(scratch_package, value) -> None:
    write(
        scratch_package,
        "scratch_ok",
        f'JOB_TYPE = "rag_lookup"\nSTATEMENT_TIMEOUT = "{value}"\ndef handle(c, j):\n    pass\n',
    )
    assert rag_handlers.iter_timeouts() == {"rag_lookup": value}


def test_a_non_string_timeout_is_permanent(scratch_package) -> None:
    write(
        scratch_package,
        "scratch_int",
        'JOB_TYPE = "rag_lookup"\nSTATEMENT_TIMEOUT = 5\ndef handle(c, j):\n    pass\n',
    )
    with pytest.raises(PermanentError, match="STATEMENT_TIMEOUT"):
        rag_handlers.iter_timeouts()
