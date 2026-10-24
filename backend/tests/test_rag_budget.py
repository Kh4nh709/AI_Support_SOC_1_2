"""P13-T03 / DEC-210, spec §7.1 "Spend" — `rag.budget`.

The RAG has its own sub-cap (`RAG_MONTHLY_USD_CAP`) and spends inside the global one
(`LLM_MONTHLY_USD_CAP`, effective through `infra.settings`, which the admin may change on the web).

* `rag_spent_usd`: this month's cost of the two RAG pipelines, and of nothing else;
* `global_exhausted`: all pipelines together reach the effective global cap, or the cap cannot be
  read (fail closed, as the adapter does);
* `rag_spent_or_exhausted`: the spend the adapter reads — `inf` when the global cap is reached or
  unreadable, the RAG's month otherwise — so that both caps are checked on every attempt;
* `rag_limits`: the limits the RAG adapter reads — the RAG cap, the effective timeout — so that the
  adapter stops a call when that spend reaches the RAG cap. Paired with `DeepSeekAdapter` below.

The rows are `llm_runs` written on the `db` fixture's transaction, which rolls back.
"""

from __future__ import annotations

import uuid
from functools import partial
from types import SimpleNamespace

import psycopg
import pytest
from app.infra import settings
from app.infra.config import Config
from app.llm.adapter import DeepSeekAdapter, LLMBudgetExceeded
from app.rag import budget

from tests.scratch_db import insert_user

pytestmark = pytest.mark.db

ROLE = {
    "triage": ("alert", "proposer"),
    "investigate": ("case", "investigator"),
    "rag_lookup": ("alert", "retriever"),
    "knowledge_draft": ("case", "drafter"),
}
CFG = Config(
    LLM_MODEL_PROPOSER="m",
    LLM_MONTHLY_USD_CAP=30,
    RAG_MONTHLY_USD_CAP=3,
    LLM_TIMEOUT_S=120,
    LLM_RETRY=0,
)


def spend(db, pipeline: str, cost: float, *, last_month: bool = False) -> None:
    subject_type, role = ROLE[pipeline]
    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt,"
        " user_message, cost_usd, created_at) VALUES (%s, %s, %s, %s, %s, 's', 'u', %s,"
        " CASE WHEN %s THEN date_trunc('month', now()) - interval '1 day' ELSE now() END)",
        (uuid.uuid4(), pipeline, subject_type, f"s-{uuid.uuid4().hex[:8]}", role, cost, last_month),
    )


def set_limit(db, key: str, value: int) -> None:
    admin = insert_user(db, "admin")
    db.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES (%s, %s, %s)", (key, value, admin)
    )


# ── rag_spent_usd ─────────────────────────────────────────────────────────────────────────────


def test_the_rag_spend_counts_only_the_two_rag_pipelines(db) -> None:
    spend(db, "rag_lookup", 0.5)
    spend(db, "knowledge_draft", 0.25)
    spend(db, "triage", 10.0)
    spend(db, "investigate", 20.0)
    assert budget.rag_spent_usd(db) == pytest.approx(0.75)


def test_the_rag_spend_is_this_months_only(db) -> None:
    spend(db, "rag_lookup", 0.5)
    spend(db, "rag_lookup", 100.0, last_month=True)
    spend(db, "knowledge_draft", 100.0, last_month=True)
    assert budget.rag_spent_usd(db) == pytest.approx(0.5)


def test_the_rag_spend_is_zero_and_a_float_when_nothing_was_spent(db) -> None:
    spent = budget.rag_spent_usd(db)
    assert spent == 0.0 and isinstance(spent, float)


def test_a_run_with_no_cost_adds_nothing(db) -> None:
    db.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, role, system_prompt,"
        " user_message) VALUES (%s, 'rag_lookup', 'alert', 'a-1', 'retriever', 's', 'u')",
        (uuid.uuid4(),),
    )
    assert budget.rag_spent_usd(db) == 0.0


# ── global_exhausted ──────────────────────────────────────────────────────────────────────────


def test_the_global_cap_is_not_reached_below_it(db) -> None:
    spend(db, "triage", 29.99)
    assert budget.global_exhausted(db, CFG) is False


def test_the_global_cap_is_reached_at_it_and_above_it(db) -> None:
    spend(db, "triage", 30.0)
    assert budget.global_exhausted(db, CFG) is True
    spend(db, "investigate", 5.0)
    assert budget.global_exhausted(db, CFG) is True


def test_every_pipeline_counts_toward_the_global_cap(db) -> None:
    spend(db, "triage", 10.0)
    spend(db, "investigate", 10.0)
    spend(db, "rag_lookup", 5.0)
    spend(db, "knowledge_draft", 5.0)
    assert budget.global_exhausted(db, CFG) is True


def test_last_months_spend_does_not_count(db) -> None:
    spend(db, "triage", 500.0, last_month=True)
    assert budget.global_exhausted(db, CFG) is False


def test_the_cap_is_the_effective_one_the_admin_may_have_changed(db) -> None:
    spend(db, "triage", 2.0)
    assert budget.global_exhausted(db, CFG) is False
    set_limit(db, "LLM_MONTHLY_USD_CAP", 1)
    assert budget.global_exhausted(db, CFG) is True


def test_unreadable_settings_count_as_exhausted(db) -> None:
    assert budget.global_exhausted(db, CFG) is False
    db.execute("ALTER TABLE settings RENAME TO settings_unreachable")  # rolled back with the test
    assert budget.global_exhausted(db, CFG) is True


def test_unavailable_settings_count_as_exhausted_whatever_the_reason(db, monkeypatch) -> None:
    def unavailable(conn, cfg):
        raise settings.SettingsUnavailable("down")

    monkeypatch.setattr(budget.settings, "effective_limits", unavailable)
    assert budget.global_exhausted(db, CFG) is True


def test_an_aborted_transaction_counts_as_exhausted(db) -> None:
    with pytest.raises(psycopg.errors.UndefinedTable):
        db.execute("SELECT * FROM no_such_table_p13t03")
    assert budget.global_exhausted(db, CFG) is True
    db.rollback()


# ── rag_spent_or_exhausted ────────────────────────────────────────────────────────────────────


def test_the_spend_the_adapter_reads_is_the_rag_spend_below_the_global_cap(db) -> None:
    spend(db, "rag_lookup", 0.5)
    spend(db, "triage", 10.0)
    value = budget.rag_spent_or_exhausted(db, CFG)
    assert value == pytest.approx(0.5) and isinstance(value, float)


def test_the_spend_the_adapter_reads_is_infinite_when_the_global_cap_is_reached(db) -> None:
    spend(db, "triage", 30.0)
    assert budget.rag_spent_or_exhausted(db, CFG) == float("inf")


def test_the_spend_the_adapter_reads_is_infinite_when_the_settings_cannot_be_read(db) -> None:
    db.execute("ALTER TABLE settings RENAME TO settings_unreachable")
    assert budget.rag_spent_or_exhausted(db, CFG) == float("inf")


def test_the_spend_the_adapter_reads_follows_the_effective_global_cap(db) -> None:
    spend(db, "triage", 2.0)
    assert budget.rag_spent_or_exhausted(db, CFG) == 0.0
    set_limit(db, "LLM_MONTHLY_USD_CAP", 1)
    assert budget.rag_spent_or_exhausted(db, CFG) == float("inf")


# ── rag_limits ────────────────────────────────────────────────────────────────────────────────


def test_the_rag_limits_carry_the_rag_cap_and_the_effective_timeout(db) -> None:
    set_limit(db, "LLM_TIMEOUT_S", 77)
    set_limit(db, "LLM_MONTHLY_USD_CAP", 500)
    limits = budget.rag_limits(db, CFG)
    assert isinstance(limits, settings.Limits)
    assert limits.cap_usd == 3 == CFG.RAG_MONTHLY_USD_CAP
    assert limits.timeout_s == 77
    assert limits.sources["LLM_TIMEOUT_S"].source == "web"
    assert limits.quota_per_24h == CFG.ANALYZE_QUOTA_PER_USER_DAY


def test_the_rag_limits_without_a_web_setting_use_the_env_timeout(db) -> None:
    limits = budget.rag_limits(db, CFG)
    assert (limits.cap_usd, limits.timeout_s) == (3, 120)


def test_the_rag_limits_follow_the_rag_cap_of_the_config_given(db) -> None:
    assert budget.rag_limits(db, Config(RAG_MONTHLY_USD_CAP=8, LLM_MONTHLY_USD_CAP=2)).cap_usd == 8


def test_the_rag_limits_fail_closed_when_the_settings_cannot_be_read(db) -> None:
    db.execute("ALTER TABLE settings RENAME TO settings_unreachable")
    with pytest.raises(settings.SettingsUnavailable):
        budget.rag_limits(db, CFG)


# ── the adapter, wired as the lookup wires it ─────────────────────────────────────────────────


class StubClient:
    """The OpenAI client's `chat.completions.create`, counting how often it is reached."""

    def __init__(self) -> None:
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls += 1
        message = SimpleNamespace(content='{"matches": []}')
        usage = SimpleNamespace(
            model_dump=lambda: {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)], usage=usage, model="m")


def rag_adapter(db, client: StubClient, cfg: Config = CFG) -> DeepSeekAdapter:
    return DeepSeekAdapter(
        cfg,
        client=client,
        spent_usd=partial(budget.rag_spent_or_exhausted, db, cfg),
        limits=partial(budget.rag_limits, db, cfg),
    )


def call(adapter: DeepSeekAdapter) -> None:
    adapter.complete(system="JSON", user="u", response_format={"type": "json_object"})


def test_the_adapter_stops_when_the_rag_spend_reaches_the_rag_cap(db) -> None:
    client = StubClient()
    spend(db, "rag_lookup", 2.0)
    spend(db, "knowledge_draft", 0.99)
    call(rag_adapter(db, client))
    assert client.calls == 1
    spend(db, "knowledge_draft", 0.01)
    with pytest.raises(LLMBudgetExceeded):
        call(rag_adapter(db, client))
    assert client.calls == 1  # no socket was opened


def test_spend_by_the_other_pipelines_does_not_use_up_the_rag_cap(db) -> None:
    client = StubClient()
    spend(db, "triage", 20.0)
    spend(db, "investigate", 9.0)
    call(rag_adapter(db, client))
    assert client.calls == 1


def test_the_adapter_stops_when_the_global_cap_is_reached_whatever_the_rag_spend(db) -> None:
    client = StubClient()
    spend(db, "triage", 30.0)  # the RAG's own month is untouched: 0 of 3
    assert budget.rag_spent_usd(db) == 0.0
    with pytest.raises(LLMBudgetExceeded):
        call(rag_adapter(db, client))
    assert client.calls == 0


def test_the_global_cap_crossed_between_two_calls_stops_the_second(db) -> None:
    """The first send is allowed; before the repair is sent the cap has been crossed by what the
    database holds (① or ②; a row stands in for them), and the repair is not sent. The cap is read
    from the database before each attempt: a call's own cost counts once its run row is written."""
    client = StubClient()
    adapter = rag_adapter(db, client)
    call(adapter)
    assert client.calls == 1
    spend(db, "triage", 30.0)
    with pytest.raises(LLMBudgetExceeded):
        call(adapter)
    assert client.calls == 1


def test_the_adapter_stops_when_the_limits_cannot_be_read(db) -> None:
    client = StubClient()
    db.execute("ALTER TABLE settings RENAME TO settings_unreachable")
    with pytest.raises(LLMBudgetExceeded):
        call(rag_adapter(db, client))
    assert client.calls == 0
