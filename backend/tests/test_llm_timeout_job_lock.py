"""The web's model timeout can never outlive the job's session — scaled (P11-T03 fix round 1,
review finding I1, DEC-202).

The failure the Reviewer measured: a job holds one transaction open while it waits on the model,
and `SET LOCAL idle_in_transaction_session_timeout` is `JOB_LOCK_TIMEOUT_S` (300 s by default).
A saved `LLM_TIMEOUT_S` above that let a slow but ANSWERED call outlive the session: Postgres
ended the worker's connection, the paid call was never written to `llm_runs` (so the monthly
cap stopped seeing it), the exception escaped `run_forever` and the worker process died.

DEC-202 bounds the web value at `settings.timeout_max(cfg)` = `(JOB_LOCK_TIMEOUT_S - 60) // 2`
(120 s at the default) and clamps a stored value to it when it is read. These tests run the REAL
worker loop over a committed ① job, scaled down so they take seconds, not minutes:

- the job lock is 4 s (it stands for 300 s), the margin is 0 and the floor 1 s (so the ceiling,
  `(4 - 0) // 2 = 2 s`, stands for 120 s). The margin and the floor are module values of
  `infra/settings.py` for exactly this reason;
- the model is a stub that sleeps, in place of the SDK client of the real `DeepSeekAdapter`.

It is built on a scratch database of its own: the worker really commits, and `llm_runs` and
`audit_events` are append-only tables the shared session database must keep clean.
"""

from __future__ import annotations

import time
from dataclasses import replace
from types import SimpleNamespace

import psycopg
import pytest
from app.infra import config, settings, worker
from app.tier1 import triage as triage_module

from tests.scratch_db import insert_user, scratch_database
from tests.test_triage_job import _enable_llm, _seed_alert

pytestmark = pytest.mark.db

_JOB_LOCK_S = 4  # stands for the default 300
_CEILING_S = 2  # stands for 120


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("p11t03_lock") as dsn:
        yield dsn


@pytest.fixture
def scaled(monkeypatch):
    _enable_llm(monkeypatch)
    monkeypatch.setenv("JOB_LOCK_TIMEOUT_S", str(_JOB_LOCK_S))
    monkeypatch.setattr(settings, "JOB_MARGIN_S", 0)
    monkeypatch.setitem(settings.BOUNDS, "LLM_TIMEOUT_S", (1, 600))
    return replace(config.Config(), JOB_LOCK_TIMEOUT_S=_JOB_LOCK_S)


class _SlowModel:
    """An SDK-shaped client for the real adapter: records the `timeout` of every call, sleeps
    `delay_s`, then answers `{}` (schema-invalid, so ① repairs once: two calls)."""

    def __init__(self, delay_s: float) -> None:
        self.timeouts: list[float] = []
        self._delay_s = delay_s
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.timeouts.append(kwargs["timeout"])
        time.sleep(self._delay_s)
        message = SimpleNamespace(content="{}", model_extra={})
        usage = {"prompt_tokens": 1000, "completion_tokens": 50}
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], model="m", usage=usage)


def _run_the_worker_once(dsn, monkeypatch, model: _SlowModel, *, saved_timeout_s: int) -> dict:
    """One real `run_forever(once=True)` cycle over one committed ① job whose saved
    `LLM_TIMEOUT_S` is `saved_timeout_s`; what it left behind, read on another connection."""
    real = triage_module.DeepSeekAdapter
    monkeypatch.setattr(
        triage_module, "DeepSeekAdapter", lambda cfg, **kw: real(cfg, client=model, **kw)
    )
    setup = psycopg.connect(dsn)
    try:
        admin = insert_user(setup, "admin")
        setup.execute(
            "INSERT INTO settings (key, value, updated_by) VALUES ('LLM_TIMEOUT_S', %s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (saved_timeout_s, admin),
        )
        alert_id = _seed_alert(setup)
        setup.commit()

        worker_conn = psycopg.connect(dsn)
        escaped = None
        try:
            worker.run_forever(
                lambda: worker_conn, {"triage": triage_module.run_triage_job}, once=True
            )
        except Exception as exc:  # noqa: BLE001 — what escapes the loop is the finding
            escaped = exc
        finally:
            worker_conn.close()

        job = setup.execute(
            "SELECT status, attempts FROM jobs WHERE subject_id = %s", (alert_id,)
        ).fetchone()
        (runs,) = setup.execute(
            "SELECT count(*) FROM llm_runs WHERE subject_id = %s", (alert_id,)
        ).fetchone()
        setup.rollback()
        return {"escaped": escaped, "job": job, "runs": runs}
    finally:
        setup.close()


def test_the_scaled_ceiling_is_what_the_formula_gives(scaled):
    assert settings.timeout_max(scaled) == _CEILING_S
    assert settings.bounds(scaled)["LLM_TIMEOUT_S"] == (1, _CEILING_S)


def test_a_model_answering_just_under_the_ceiling_is_recorded_and_the_worker_lives(
    scratch_dsn, scaled, monkeypatch
):
    """The web timeout at its derived maximum (2 s), a model answering at 1.2 s: both sends fit
    the session, the answered calls are recorded and the loop does not raise. (The two sends
    are ① the proposer and its one repair.)"""
    model = _SlowModel(1.2)

    out = _run_the_worker_once(scratch_dsn, monkeypatch, model, saved_timeout_s=_CEILING_S)

    assert out["escaped"] is None, f"the worker loop let {out['escaped']!r} out"
    assert model.timeouts == [_CEILING_S, _CEILING_S]
    assert out["job"] == ("succeeded", 1)
    assert out["runs"] >= 1, "the answered calls left no llm_runs row"


def test_a_saved_timeout_above_the_ceiling_is_cut_by_the_adapter_and_not_by_postgres(
    scratch_dsn, scaled, monkeypatch
):
    """The Reviewer's probe, scaled: a saved 10 s (it stands for 600 s) over a 4 s job lock, and
    a model that answers only after 5 s. Read, the value is held to the 2 s ceiling, so the
    ADAPTER abandons the call at 2 s (a transient timeout: the job is rescheduled) — long before
    Postgres would end the session at 4 s. Without the clamp the call runs under a 10 s
    deadline, Postgres kills the connection and the exception escapes the loop. Red step: put the
    static 600 back as the ceiling and this fails."""
    model = _SlowModel(5.0)

    out = _run_the_worker_once(scratch_dsn, monkeypatch, model, saved_timeout_s=10)

    assert out["escaped"] is None, f"the worker loop let {out['escaped']!r} out"
    assert out["job"] == ("pending", 1)  # rescheduled, not stuck `running`
    assert out["runs"] == 0  # nothing was answered, so nothing is owed to `llm_runs`
    assert model.timeouts == [_CEILING_S], "the stored 10 s was not clamped to the ceiling"
