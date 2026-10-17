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
    bounds,
    effective_limits,
    from_config,
    timeout_max,
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
        "timeout_max",  # DEC-202: the bound the timeout was held to (defaulted)
    ]
    assert [f.name for f in dataclasses.fields(LimitSource)] == [
        "source",
        "updated_at",
        "updated_by",
        "clamped",  # DEC-202 (defaulted False)
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
        assert source.clamped is False


# ── DEC-202: the timeout is bounded by the job lock ───────────────────────────────────────


@pytest.mark.parametrize(
    ("job_lock_timeout_s", "expected"),
    [
        (300, 120),  # the default: two sends of 120 s and the 60 s margin
        (200, 70),
        (1000, 470),
        (1260, 600),  # the Owner's static ceiling is reached exactly here
        (5000, 600),  # ... and never passed
        (140, 40),
        (80, 10),  # the floor starts to hold
        (60, 10),
        (0, 10),
    ],
)
def test_timeout_max_is_the_job_lock_less_the_margin_split_over_two_sends(
    job_lock_timeout_s, expected
):
    assert timeout_max(replace(_CFG, JOB_LOCK_TIMEOUT_S=job_lock_timeout_s)) == expected


def test_two_sends_at_the_timeout_max_always_fit_under_the_job_lock_with_the_margin():
    """The invariant `tier2/investigate.py:19-33` states: 2 x LLM_TIMEOUT_S + 60 s <= the job
    lock — for every job lock from the point the floor of 10 s stops mattering."""
    for lock in range(80, 3000):
        cfg = replace(_CFG, JOB_LOCK_TIMEOUT_S=lock)
        assert 2 * timeout_max(cfg) + 60 <= lock, lock
        assert 10 <= timeout_max(cfg) <= 600


def test_bounds_is_the_static_envelope_with_the_timeout_ceiling_derived():
    assert bounds(_CFG) == {
        "LLM_MONTHLY_USD_CAP": (1, 1000),
        "ANALYZE_QUOTA_PER_USER_DAY": (1, 200),
        "LLM_TIMEOUT_S": (10, 120),
    }
    assert bounds(replace(_CFG, JOB_LOCK_TIMEOUT_S=200))["LLM_TIMEOUT_S"] == (10, 70)
    assert bounds(replace(_CFG, JOB_LOCK_TIMEOUT_S=5000))["LLM_TIMEOUT_S"] == (10, 600)
    assert BOUNDS["LLM_TIMEOUT_S"] == (10, 600)  # the envelope itself is untouched


def test_from_config_carries_the_ceiling_and_never_clamps_the_env_value():
    cfg = replace(_CFG, LLM_TIMEOUT_S=500, JOB_LOCK_TIMEOUT_S=300)  # an Owner's choice

    limits = from_config(cfg)

    assert limits.timeout_s == 500  # the `.env` value is the Owner's: not clamped
    assert limits.timeout_max == 120
    assert limits.sources["LLM_TIMEOUT_S"].clamped is False


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
def test_a_stored_timeout_above_the_ceiling_is_clamped_on_read_and_says_so(db):
    """DEC-202: a saved 600 s (stored before the bound, or under a larger `JOB_LOCK_TIMEOUT_S`
    that was lowered later) would outlive the job's session. Read, it is held to the ceiling;
    the stored row is untouched and the source still says `web`, with the clamp reported."""
    admin = _make_user(db)
    _set(db, "LLM_TIMEOUT_S", 600, admin)

    limits = effective_limits(db, _CFG)  # JOB_LOCK_TIMEOUT_S 300: ceiling 120

    assert limits.timeout_s == 120 and limits.timeout_max == 120
    source = limits.sources["LLM_TIMEOUT_S"]
    assert (source.source, source.clamped, source.updated_by) == ("web", True, admin)
    assert db.execute("SELECT value FROM settings WHERE key = 'LLM_TIMEOUT_S'").fetchone() == (600,)


@pytest.mark.db
def test_a_stored_timeout_at_or_below_the_ceiling_is_not_clamped(db):
    admin = _make_user(db)
    for stored in (10, 119, 120):
        _set(db, "LLM_TIMEOUT_S", stored, admin)
        limits = effective_limits(db, _CFG)
        assert limits.timeout_s == stored
        assert limits.sources["LLM_TIMEOUT_S"].clamped is False


@pytest.mark.db
def test_the_ceiling_follows_the_configured_job_lock_on_every_read(db):
    admin = _make_user(db)
    _set(db, "LLM_TIMEOUT_S", 100, admin)

    at_300 = effective_limits(db, _CFG)
    at_200 = effective_limits(db, replace(_CFG, JOB_LOCK_TIMEOUT_S=200))  # ceiling 70

    assert (at_300.timeout_s, at_300.sources["LLM_TIMEOUT_S"].clamped) == (100, False)
    assert (at_200.timeout_s, at_200.sources["LLM_TIMEOUT_S"].clamped) == (70, True)
    assert at_200.timeout_max == 70


@pytest.mark.db
def test_only_the_timeout_is_clamped_never_the_cap_or_the_quota(db):
    admin = _make_user(db)
    _set(db, "LLM_MONTHLY_USD_CAP", 1000, admin)
    _set(db, "ANALYZE_QUOTA_PER_USER_DAY", 200, admin)

    limits = effective_limits(db, replace(_CFG, JOB_LOCK_TIMEOUT_S=60))

    assert (limits.cap_usd, limits.quota_per_24h) == (1000, 200)
    assert {s.clamped for s in limits.sources.values()} == {False}


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
