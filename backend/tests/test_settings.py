"""`app.infra.settings` — the one fail-closed accessor of the three editable LLM limits
(P11-T03, DEC-200 item 3, spec §5.2).

What is pinned here:
- the exact public names later tasks import (`KEYS`, `BOUNDS`, `Limits`, ...);
- `from_config` is the `.env` view, every source `env`;
- `effective_limits` reads the `settings` table on every call (no cache): a row wins, a missing
  row keeps the `.env` value, and a read that fails raises `SettingsUnavailable` — never a
  silent `.env` fallback;
- the read runs in a savepoint, so a failed read leaves the CALLER'S transaction usable,
  including when the `settings` table does not exist (code deployed before `make migrate`);
- no reader outside `infra/config.py` and `infra/settings.py` touches the three `Config`
  attributes (the guard test at the bottom).
"""

from __future__ import annotations

import dataclasses
import pathlib
import re
import uuid
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace

import psycopg
import pytest
from app.infra.config import Config
from app.infra.settings import (
    BOUNDS,
    KEYS,
    Limits,
    LimitSource,
    SettingsUnavailable,
    effective_limits,
    from_config,
)

_CFG = Config(LLM_MONTHLY_USD_CAP=30, ANALYZE_QUOTA_PER_USER_DAY=25, LLM_TIMEOUT_S=120)


def _make_user(conn: psycopg.Connection, *, role: str = "admin") -> str:
    user_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, %s, %s, %s, 'x')",
        (user_id, f"user-{user_id[:8]}", "Test Admin", role),
    )
    return user_id


def _set(conn: psycopg.Connection, key: str, value: int, user_id: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value, updated_by) VALUES (%s, %s, %s) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), "
        "updated_by = EXCLUDED.updated_by",
        (key, value, user_id),
    )


class _FailingConn:
    """Just enough of a psycopg connection for `effective_limits`: `transaction()` is a
    no-op context manager and `execute` raises `exc`."""

    info = SimpleNamespace(transaction_status=psycopg.pq.TransactionStatus.INTRANS)

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.executed: list[str] = []

    @contextmanager
    def transaction(self):
        yield self

    def execute(self, query, *args, **kwargs):
        self.executed.append(str(query))
        raise self._exc


# ── the contract later tasks rely on (no database) ────────────────────────────────────────


def test_the_public_names_and_bounds_are_exactly_the_documented_ones():
    assert KEYS == ("LLM_MONTHLY_USD_CAP", "ANALYZE_QUOTA_PER_USER_DAY", "LLM_TIMEOUT_S")
    assert BOUNDS == {
        "LLM_MONTHLY_USD_CAP": (1, 1000),
        "ANALYZE_QUOTA_PER_USER_DAY": (1, 200),
        "LLM_TIMEOUT_S": (10, 600),
    }
    assert issubclass(SettingsUnavailable, Exception)
    assert dataclasses.is_dataclass(Limits) and dataclasses.is_dataclass(LimitSource)
    assert [f.name for f in dataclasses.fields(Limits)] == [
        "cap_usd",
        "quota_per_24h",
        "timeout_s",
        "sources",
    ]
    assert [f.name for f in dataclasses.fields(LimitSource)] == [
        "source",
        "updated_at",
        "updated_by",
    ]


def test_limits_are_frozen():
    limits = from_config(_CFG)
    with pytest.raises(dataclasses.FrozenInstanceError):
        limits.cap_usd = 1  # type: ignore[misc]


def test_from_config_is_the_env_view_with_every_source_env():
    limits = from_config(_CFG)

    assert (limits.cap_usd, limits.quota_per_24h, limits.timeout_s) == (30, 25, 120)
    assert set(limits.sources) == set(KEYS)
    for source in limits.sources.values():
        assert source == LimitSource(source="env", updated_at=None, updated_by=None)


def test_a_read_error_is_settings_unavailable_and_never_a_env_fallback():
    conn = _FailingConn(psycopg.OperationalError("server closed the connection unexpectedly"))

    with pytest.raises(SettingsUnavailable) as info:
        effective_limits(conn, _CFG)

    assert conn.executed, "the accessor must have tried to read before giving up"
    assert isinstance(info.value.__cause__, psycopg.OperationalError)


def test_an_undefined_table_is_settings_unavailable():
    conn = _FailingConn(psycopg.errors.UndefinedTable('relation "settings" does not exist'))

    with pytest.raises(SettingsUnavailable):
        effective_limits(conn, _CFG)


# ── the table (database) ──────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_no_rows_is_exactly_from_config(db):
    assert effective_limits(db, _CFG) == from_config(_CFG)


@pytest.mark.db
def test_one_row_overrides_one_key_and_marks_its_source_web(db):
    admin = _make_user(db)
    _set(db, "LLM_MONTHLY_USD_CAP", 77, admin)

    limits = effective_limits(db, _CFG)

    assert limits.cap_usd == 77
    assert (limits.quota_per_24h, limits.timeout_s) == (25, 120)  # the other two stay on `.env`
    web = limits.sources["LLM_MONTHLY_USD_CAP"]
    assert web.source == "web"
    assert web.updated_by == admin
    assert isinstance(web.updated_at, datetime)
    assert limits.sources["ANALYZE_QUOTA_PER_USER_DAY"].source == "env"
    assert limits.sources["LLM_TIMEOUT_S"] == LimitSource("env", None, None)


@pytest.mark.db
def test_all_three_rows_override_all_three_keys(db):
    admin = _make_user(db)
    _set(db, "LLM_MONTHLY_USD_CAP", 5, admin)
    _set(db, "ANALYZE_QUOTA_PER_USER_DAY", 6, admin)
    _set(db, "LLM_TIMEOUT_S", 70, admin)

    limits = effective_limits(db, _CFG)

    assert (limits.cap_usd, limits.quota_per_24h, limits.timeout_s) == (5, 6, 70)
    assert {s.source for s in limits.sources.values()} == {"web"}


@pytest.mark.db
def test_there_is_no_cache_a_save_is_seen_on_the_next_call(db):
    admin = _make_user(db)
    assert effective_limits(db, _CFG).cap_usd == 30

    _set(db, "LLM_MONTHLY_USD_CAP", 40, admin)
    assert effective_limits(db, _CFG).cap_usd == 40

    _set(db, "LLM_MONTHLY_USD_CAP", 41, admin)
    assert effective_limits(db, _CFG).cap_usd == 41

    db.execute("DELETE FROM settings WHERE key = 'LLM_MONTHLY_USD_CAP'")
    after_delete = effective_limits(db, _CFG)
    assert (
        after_delete.cap_usd == 30 and after_delete.sources["LLM_MONTHLY_USD_CAP"].source == "env"
    )


@pytest.mark.db
def test_the_env_value_follows_the_config_it_is_given_when_no_row_exists(db):
    other = replace(_CFG, LLM_MONTHLY_USD_CAP=99)

    assert effective_limits(db, other).cap_usd == 99


@pytest.mark.db
def test_a_successful_read_neither_commits_nor_ends_the_callers_transaction(db):
    """The read is a savepoint inside the caller's transaction: what the caller wrote before it
    is still uncommitted, so a rollback takes it away."""
    admin = _make_user(db)
    assert db.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS

    effective_limits(db, _CFG)

    assert db.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS
    assert db.execute("SELECT count(*) FROM users WHERE user_id = %s", (admin,)).fetchone() == (1,)
    db.rollback()
    assert db.execute("SELECT count(*) FROM users WHERE user_id = %s", (admin,)).fetchone() == (0,)


@pytest.mark.db
def test_a_missing_settings_table_raises_and_leaves_the_callers_transaction_usable(db):
    """Code deployed before `make migrate`: the table is absent. The failed statement must not
    abort the caller's transaction (the savepoint), and what the caller wrote earlier survives:
    this is what lets a job still write its `llm_runs` row after the model call was refused."""
    admin = _make_user(db)
    db.execute("DROP TABLE settings")  # rolled back with the test's transaction

    with pytest.raises(SettingsUnavailable) as info:
        effective_limits(db, _CFG)

    assert isinstance(info.value.__cause__, psycopg.errors.UndefinedTable)
    # The pin: a following statement runs, and the earlier write is still there.
    assert db.execute("SELECT 1").fetchone() == (1,)
    assert db.execute("SELECT count(*) FROM users WHERE user_id = %s", (admin,)).fetchone() == (1,)
    assert db.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS


@pytest.mark.db
def test_a_second_failed_read_in_the_same_transaction_is_just_as_usable(db):
    db.execute("DROP TABLE settings")
    for _ in range(2):
        with pytest.raises(SettingsUnavailable):
            effective_limits(db, _CFG)
        assert db.execute("SELECT 1").fetchone() == (1,)


@pytest.mark.db
def test_a_read_in_a_transaction_that_is_already_failed_is_settings_unavailable(db):
    """The caller's transaction was aborted before the call. The accessor says so and leaves the
    connection alone — it can still be rolled back and used (psycopg would otherwise keep a
    half-entered `transaction()` block on its books and refuse every `rollback()` after it)."""
    with pytest.raises(psycopg.errors.UndefinedTable):
        db.execute("SELECT * FROM no_such_table_p11t03")  # the caller's own failure

    with pytest.raises(SettingsUnavailable):
        effective_limits(db, _CFG)

    db.rollback()
    assert db.execute("SELECT 1").fetchone() == (1,)


# ── the guard: no reader of the three keys outside the config and the accessor ────────────

_APP = pathlib.Path(__file__).resolve().parents[1] / "app"
_ALLOWED = {_APP / "infra" / "config.py", _APP / "infra" / "settings.py"}
_ATTRIBUTE_ACCESS = re.compile(
    r"\.(LLM_MONTHLY_USD_CAP|ANALYZE_QUOTA_PER_USER_DAY|LLM_TIMEOUT_S)\b"
)


def _offenders(files: dict[pathlib.Path, str]) -> list[str]:
    found = []
    for path, text in sorted(files.items()):
        if path in _ALLOWED:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if _ATTRIBUTE_ACCESS.search(line):
                found.append(f"{path.relative_to(_APP)}:{number}: {line.strip()}")
    return found


def test_no_attribute_access_to_the_three_keys_outside_config_and_settings():
    files = {p: p.read_text(encoding="utf-8") for p in _APP.rglob("*.py")}

    assert _offenders(files) == []


def test_the_guard_does_catch_an_attribute_access():
    """The guard is not vacuous: the same scan, fed a file that reads `cfg.LLM_TIMEOUT_S`, names it."""
    fake = _APP / "llm" / "some_new_reader.py"
    files = {fake: "deadline = cfg.LLM_TIMEOUT_S\nother = cfg.LLM_MONTHLY_USD_CAP + 1\n"}

    assert _offenders(files) == [
        "llm/some_new_reader.py:1: deadline = cfg.LLM_TIMEOUT_S",
        "llm/some_new_reader.py:2: other = cfg.LLM_MONTHLY_USD_CAP + 1",
    ]
