"""Tests for app.ingest.autoclose — G8' hard blocks, whitelist matching, the rule
cache, `simulate`, and the layer-2 width report.

Every db-marked test that touches `autoclose_rules` inserts the `t09` user first
(design note 8): `autoclose_rules.created_by` carries `fk_autoclose_created_by`
(migration 007), so a rule INSERT with a random uuid fails with
`violates foreign key constraint "fk_autoclose_created_by"` before this module
ever sees the row. `TEST_DATABASE_URL=postgresql:///soc_p2t09_test` on every
db-marked pytest invocation (design note 9, DEC-023 item 8).

The rule cache (`app.ingest.autoclose._rule_cache`) is module-global state — the
autouse `_reset_rule_cache` fixture below resets it before and after every test
so one test's cached rules never leak into the next.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import time
import uuid
from datetime import UTC, datetime

import psycopg
import pytest
from app.domain.alert import Alert, AlertContext
from app.infra import config
from app.infra.errors import PermanentError
from app.ingest import autoclose
from psycopg.types.json import Jsonb

T09_USER_ID = "00000000-0000-0000-0000-00000000aaaa"
_ALERT_TIME = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _reset_rule_cache():
    autoclose._rule_cache = None
    yield
    autoclose._rule_cache = None


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def _alert(**overrides) -> Alert:
    fields = {
        "alert_id": "a-1",
        "manager_id": "IA1803",
        "rule_id": "40112",
        "description": "d",
        "agent_name": "user1-IA1803",
        "agent_id": "001",
        "agent_ip": None,
        "origin_host": "user1-IA1803",
        "alert_time": _ALERT_TIME,
        "event_time": None,
        "srcip": "127.0.0.1",
        "dstip": "",
        "src_port": 48104,
        "dst_port": 0,
        "alert_user": "user1",
        "decoder": "sshd",
        "mitre_ids": (),
        "rule_groups": (),
        "rule_level": 5,
        "severity": "medium",
        "category": "generic",
        "categories": (),
        "resolved_by": "none",
        "mapping_version": "v1",
        "srcip_is_private": True,
        "dstip_is_private": None,
        "raw_log": "log",
        "raw_log_truncated": False,
        "event_bucket_hash": "0" * 64,
        "raw_payload": {},
    }
    fields.update(overrides)
    return Alert(**fields)


def _ctx(**overrides) -> AlertContext:
    fields = {
        "asset_present": True,
        "asset_criticality": "medium",
        "asset_owner": None,
        "asset_role": None,
        "identity_privileged": False,
        "ioc_reputation": "not_found",
        "lookup_status": {"asset": "found", "identity": "found", "ioc": "not_found"},
    }
    fields.update(overrides)
    return AlertContext(**fields)


def _everything_rule(rule_id: str = "everything") -> autoclose.Rule:
    return autoclose.Rule(rule_id=rule_id, name="everything", reason="t", conditions=())


def _set_never_autoclose(monkeypatch: pytest.MonkeyPatch, agents: list[str]) -> None:
    monkeypatch.setenv("NEVER_AUTOCLOSE_AGENTS", json.dumps(agents))


def _seed_user(conn: psycopg.Connection) -> None:
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, 't09', 't09', 'admin', 'x')",
        (T09_USER_ID,),
    )


def _insert_rule(
    conn: psycopg.Connection,
    *,
    rule_id: str,
    match: object,
    name: str = "r",
    reason: str = "t",
    created_at: str = "2026-09-06 00:00:00+00",
    enabled: bool = True,
) -> None:
    conn.execute(
        "INSERT INTO autoclose_rules "
        "(autoclose_rule_id, name, enabled, match, reason, created_by, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (rule_id, name, enabled, Jsonb(match), reason, T09_USER_ID, created_at),
    )


def _insert_alert_row(
    conn: psycopg.Connection,
    *,
    alert_id: str,
    severity: str = "medium",
    agent_name: str = "user1-IA1803",
    rule_id: str = "1",
    category: str = "generic",
    rule_level: int = 5,
    occurrence_count: int = 1,
    status: str = "received",
    is_synthetic: bool = False,
    duplicate_of: str | None = None,
    asset_context: dict | None = None,
    identity_context: dict | None = None,
    ioc_context: dict | None = None,
    autoclose_rule_id: str | None = None,
    srcip: str = "",
    dstip: str = "",
    dst_port: int = 0,
    src_port: int = 0,
    agent_id: str | None = None,
    alert_user: str | None = None,
    decoder: str | None = None,
) -> None:
    event_bucket_hash = hashlib.sha256(alert_id.encode()).hexdigest()
    conn.execute(
        """
        INSERT INTO alerts (
            alert_id, rule_id, rule_level, severity, description, agent_name, alert_time,
            category, resolved_by, mapping_version, event_bucket_hash, raw_payload,
            status, occurrence_count, is_synthetic, duplicate_of,
            closed_at, sealed_at, received_at,
            srcip, dstip, dst_port, src_port, agent_id, alert_user, decoder,
            asset_context, identity_context, ioc_context, autoclose_rule_id
        ) VALUES (
            %(alert_id)s, %(rule_id)s, %(rule_level)s, %(severity)s, 'd', %(agent_name)s, now(),
            %(category)s, 'none', 'v1', %(event_bucket_hash)s, %(raw_payload)s,
            %(status)s, %(occurrence_count)s, %(is_synthetic)s, %(duplicate_of)s,
            CASE WHEN %(status)s = 'received' THEN NULL ELSE now() END,
            NULL,
            now(),
            %(srcip)s, %(dstip)s, %(dst_port)s, %(src_port)s, %(agent_id)s, %(alert_user)s,
            %(decoder)s, %(asset_context)s, %(identity_context)s, %(ioc_context)s,
            %(autoclose_rule_id)s
        )
        """,
        {
            "alert_id": alert_id,
            "rule_id": rule_id,
            "rule_level": rule_level,
            "severity": severity,
            "agent_name": agent_name,
            "category": category,
            "event_bucket_hash": event_bucket_hash,
            "raw_payload": Jsonb({}),
            "status": status,
            "occurrence_count": occurrence_count,
            "is_synthetic": is_synthetic,
            "duplicate_of": duplicate_of,
            "srcip": srcip,
            "dstip": dstip,
            "dst_port": dst_port,
            "src_port": src_port,
            "agent_id": agent_id,
            "alert_user": alert_user,
            "decoder": decoder,
            "asset_context": Jsonb(asset_context) if asset_context is not None else None,
            "identity_context": Jsonb(identity_context) if identity_context is not None else None,
            "ioc_context": Jsonb(ioc_context) if ioc_context is not None else None,
            "autoclose_rule_id": autoclose_rule_id,
        },
    )


class _BoomConn:
    """A conn whose every query raises — proves fail-open without a real database."""

    def execute(self, *_args, **_kwargs):
        raise psycopg.OperationalError("boom")


# ---------------------------------------------------------------------------
# G8' — match-everything rule still blocked (acceptance 2; "test with a rule
# that matches everything" per context pack G8')
# ---------------------------------------------------------------------------


def test_match_everything_rule_still_blocked_by_never_autoclose_agent(monkeypatch):
    _set_never_autoclose(monkeypatch, ["bad-agent"])
    alert = _alert(severity="high", agent_name="bad-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by == "never_autoclose_agent"
    assert decision.match is None


def test_match_everything_rule_still_blocked_by_asset_high(monkeypatch):
    _set_never_autoclose(monkeypatch, [])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="high",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by == "asset_high"
    assert decision.match is None


def test_match_everything_rule_still_blocked_by_asset_not_in_inventory(monkeypatch):
    _set_never_autoclose(monkeypatch, [])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=False,
        asset_criticality="unknown",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by == "asset_not_in_inventory"
    assert decision.match is None


def test_match_everything_rule_still_blocked_by_identity_privileged(monkeypatch):
    _set_never_autoclose(monkeypatch, [])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=True,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by == "identity_privileged"
    assert decision.match is None


def test_match_everything_rule_still_blocked_by_ioc_bad(monkeypatch):
    _set_never_autoclose(monkeypatch, [])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation="suspicious",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by == "ioc_bad"
    assert decision.match is None


def test_match_everything_rule_matches_the_closable_alert(monkeypatch):
    """The seventh case of design note 8: non-critical, not on the never-close
    list, asset medium and present, identity not privileged, IoC not_found —
    the only one of the seven the match-everything rule actually closes."""
    _set_never_autoclose(monkeypatch, [])
    alert = _alert(severity="medium", agent_name="normal-agent", alert_user="user1")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by is None
    assert decision.match is not None
    assert decision.match.rule_id == "everything"


@pytest.mark.db
def test_match_everything_rule_still_blocked_by_critical_and_writes_audit_event(db, monkeypatch):
    _set_never_autoclose(monkeypatch, [])
    alert = _alert(alert_id="crit-1", severity="critical", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    rule = _everything_rule("11111111-1111-1111-1111-111111111111")
    decision = autoclose.evaluate(db, alert, ctx, rules=[rule])
    assert decision.blocked_by == "critical"
    assert decision.match is None
    row = db.execute(
        "SELECT event_type, subject_id, actor_role, payload FROM audit_events "
        "WHERE subject_id = %s",
        (alert.alert_id,),
    ).fetchone()
    assert row == (
        "alert.autoclose_blocked_critical",
        "crit-1",
        "system",
        {"rule_id": rule.rule_id},
    )


@pytest.mark.db
def test_critical_alert_with_no_matching_rule_writes_no_audit_event(db, monkeypatch):
    _set_never_autoclose(monkeypatch, [])
    alert = _alert(alert_id="crit-2", severity="critical", agent_name="normal-agent")
    ctx = _ctx()
    # A rule that requires agent_name == "someone-else" never matches this alert.
    decision = autoclose.evaluate(db, alert, ctx, rules=[])
    assert decision.blocked_by == "critical"
    count = db.execute(
        "SELECT count(*) FROM audit_events WHERE subject_id = %s", (alert.alert_id,)
    ).fetchone()[0]
    assert count == 0


# ---------------------------------------------------------------------------
# Order (acceptance 3) — six alerts, each tripping one more block than the last,
# from the front. Pure: `rules=[]` never triggers the critical-block audit write.
# ---------------------------------------------------------------------------


def test_order_all_six_blocks_at_once_returns_critical(monkeypatch):
    _set_never_autoclose(monkeypatch, ["bad-agent"])
    alert = _alert(severity="critical", agent_name="bad-agent")
    ctx = _ctx(
        asset_present=False,
        asset_criticality="high",
        identity_privileged=True,
        ioc_reputation="malicious",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[])
    assert decision.blocked_by == "critical"
    assert decision.match is None


def test_order_blocks_two_through_six_returns_never_autoclose_agent(monkeypatch):
    _set_never_autoclose(monkeypatch, ["bad-agent"])
    alert = _alert(severity="high", agent_name="bad-agent")
    ctx = _ctx(
        asset_present=False,
        asset_criticality="high",
        identity_privileged=True,
        ioc_reputation="malicious",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[])
    assert decision.blocked_by == "never_autoclose_agent"


def test_order_blocks_three_through_six_returns_asset_high(monkeypatch):
    _set_never_autoclose(monkeypatch, ["bad-agent"])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=False,
        asset_criticality="high",
        identity_privileged=True,
        ioc_reputation="malicious",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[])
    assert decision.blocked_by == "asset_high"


def test_order_blocks_four_through_six_returns_asset_not_in_inventory(monkeypatch):
    _set_never_autoclose(monkeypatch, ["bad-agent"])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=False,
        asset_criticality="medium",
        identity_privileged=True,
        ioc_reputation="malicious",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[])
    assert decision.blocked_by == "asset_not_in_inventory"


def test_order_blocks_five_through_six_returns_identity_privileged(monkeypatch):
    _set_never_autoclose(monkeypatch, ["bad-agent"])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=True,
        ioc_reputation="malicious",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[])
    assert decision.blocked_by == "identity_privileged"


def test_order_block_six_only_returns_ioc_bad(monkeypatch):
    _set_never_autoclose(monkeypatch, ["bad-agent"])
    alert = _alert(severity="high", agent_name="normal-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation="malicious",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[])
    assert decision.blocked_by == "ioc_bad"


# ---------------------------------------------------------------------------
# Determinism and ordering — A3 (acceptance 4)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_earlier_created_at_wins(db):
    _seed_user(db)
    _insert_rule(
        db, rule_id=str(uuid.uuid4()), match=[], name="later", created_at="2026-09-06 00:00:01+00"
    )
    earlier_id = str(uuid.uuid4())
    _insert_rule(
        db, rule_id=earlier_id, match=[], name="earlier", created_at="2026-09-06 00:00:00+00"
    )
    rules = autoclose.load_rules(db)
    decision = autoclose.evaluate(db, _alert(), _ctx(), rules=rules)
    assert decision.match is not None
    assert decision.match.rule_id == earlier_id


@pytest.mark.db
def test_tie_smaller_id_wins(db):
    _seed_user(db)
    same_created_at = "2026-09-06 00:00:00+00"
    _insert_rule(
        db,
        rule_id="00000000-0000-0000-0000-000000000002",
        match=[],
        name="b",
        created_at=same_created_at,
    )
    _insert_rule(
        db,
        rule_id="00000000-0000-0000-0000-000000000001",
        match=[],
        name="a",
        created_at=same_created_at,
    )
    rules = autoclose.load_rules(db)
    decision = autoclose.evaluate(db, _alert(), _ctx(), rules=rules)
    assert decision.match is not None
    assert decision.match.rule_id == "00000000-0000-0000-0000-000000000001"


def test_hundred_runs_one_result():
    rules = [_everything_rule("r1"), _everything_rule("r2")]
    alert = _alert()
    ctx = _ctx()
    results = [autoclose.evaluate(None, alert, ctx, rules=rules) for _ in range(100)]
    assert len({d.match.rule_id for d in results}) == 1


# ---------------------------------------------------------------------------
# The whitelist and its operators (acceptance 5, 6)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_rules_with_disallowed_field_or_operator_are_skipped_with_warning(db, caplog):
    _seed_user(db)
    _insert_rule(
        db,
        rule_id=str(uuid.uuid4()),
        name="bad-field",
        match=[{"field": "risk_score", "op": "lte", "value": 10}],
    )
    _insert_rule(
        db,
        rule_id=str(uuid.uuid4()),
        name="bad-op",
        match=[{"field": "srcip", "op": "regex", "value": ".*"}],
    )
    with caplog.at_level(logging.WARNING, logger="app.ingest.autoclose"):
        rules = autoclose.load_rules(db)
    assert rules == []
    assert "risk_score" in caplog.text
    assert "regex" in caplog.text


@pytest.mark.db
def test_cidr_and_rule_level_conditions_combine_with_and_not_or(db):
    _seed_user(db)
    _insert_rule(
        db,
        rule_id=str(uuid.uuid4()),
        name="internal-scanner",
        match=[
            {"field": "srcip", "op": "cidr", "value": "10.0.0.0/8"},
            {"field": "rule_level", "op": "lte", "value": 7},
        ],
    )
    rules = autoclose.load_rules(db)
    assert len(rules) == 1

    ctx = _ctx()
    inside_and_low = autoclose.evaluate(
        db, _alert(srcip="10.1.2.3", rule_level=5, severity="medium"), ctx, rules=rules
    )
    assert inside_and_low.match is not None

    inside_but_high = autoclose.evaluate(
        db, _alert(srcip="10.1.2.3", rule_level=9, severity="medium"), ctx, rules=rules
    )
    assert inside_but_high.match is None


@pytest.mark.db
def test_invalid_match_rule_skipped_next_rule_still_applies(db):
    """A8 failing case: `match` is the JSON string `"not json"`, not a list —
    the whole rule is skipped, and the next enabled rule still applies."""
    _seed_user(db)
    _insert_rule(
        db,
        rule_id=str(uuid.uuid4()),
        name="broken",
        match="not json",
        created_at="2026-09-06 00:00:00+00",
    )
    _insert_rule(
        db,
        rule_id=str(uuid.uuid4()),
        name="fallback",
        match=[],
        created_at="2026-09-06 00:00:01+00",
    )
    rules = autoclose.load_rules(db)
    assert [r.name for r in rules] == ["fallback"]
    decision = autoclose.evaluate(db, _alert(), _ctx(), rules=rules)
    assert decision.match is not None
    assert decision.match.name == "fallback"


@pytest.mark.db
def test_dst_port_zero_matches_literal_zero_not_every_alert(db):
    """C2: `dst_port = 0` means "no data", but a rule that names it literally
    still matches only alerts whose stored value is exactly 0."""
    _seed_user(db)
    _insert_rule(
        db,
        rule_id=str(uuid.uuid4()),
        name="no-dst-port",
        match=[{"field": "dst_port", "op": "eq", "value": 0}],
    )
    rules = autoclose.load_rules(db)
    ctx = _ctx()
    zero = autoclose.evaluate(db, _alert(dst_port=0), ctx, rules=rules)
    assert zero.match is not None
    nonzero = autoclose.evaluate(db, _alert(dst_port=443), ctx, rules=rules)
    assert nonzero.match is None


def test_module_source_has_no_regex_or_is_private_operator_support():
    """The three deliberate exclusions (design note 3) — a Python-level mirror
    of acceptance 6's grep, so a regression fails `make test` too."""
    source = inspect.getsource(autoclose)
    assert "srcip_is_private" not in source
    assert "dstip_is_private" not in source
    assert '"regex"' not in source and "'regex'" not in source


# ---------------------------------------------------------------------------
# DEC-012's own numbers, encoded (design note 8)
# ---------------------------------------------------------------------------


def test_dec012_ia1803_high_criticality_blocked_by_asset_high():
    alert = _alert(agent_name="IA1803", severity="medium")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="high",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[])
    assert decision.blocked_by == "asset_high"
    assert decision.match is None


def test_dec012_user1_ia1803_medium_non_privileged_is_closable():
    alert = _alert(agent_name="user1-IA1803", alert_user="user1", severity="medium")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule("r-everything")])
    assert decision.blocked_by is None
    assert decision.match is not None
    assert decision.match.rule_id == "r-everything"


# ---------------------------------------------------------------------------
# Present-with-unknown vs absent (DEC-058/063/066 — the block's *behaviour* is
# not this card's to soften; these two tests only pin the existing distinction
# inventory-format.md §1 already draws)
# ---------------------------------------------------------------------------


def test_asset_present_with_unknown_criticality_is_not_the_same_as_absent():
    alert = _alert(severity="medium", agent_name="some-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="unknown",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by is None
    assert decision.match is not None


def test_asset_absent_is_blocked_even_with_unknown_criticality():
    alert = _alert(severity="medium", agent_name="some-agent")
    ctx = _ctx(
        asset_present=False,
        asset_criticality="unknown",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by == "asset_not_in_inventory"
    assert decision.match is None


@pytest.mark.parametrize("reputation", ["clean", "not_found", "skipped"])
def test_ioc_reputation_non_bad_values_are_not_blocked(reputation):
    alert = _alert(severity="medium", agent_name="some-agent")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation=reputation,
    )
    decision = autoclose.evaluate(None, alert, ctx, rules=[_everything_rule()])
    assert decision.blocked_by is None
    assert decision.match is not None


# ---------------------------------------------------------------------------
# Fail-open (acceptance 7, A8)
# ---------------------------------------------------------------------------


def test_evaluate_with_empty_rules_list_no_match():
    decision = autoclose.evaluate(None, _alert(), _ctx(), rules=[])
    assert decision.blocked_by is None
    assert decision.match is None


def test_load_rules_propagates_query_errors_it_does_not_swallow_them():
    """`load_rules` itself does not decide the fail-open policy for a dead
    connection — `_cached_rules`/`reload_rules` do (see the next test). This
    keeps a real bug in the SQL loud during development instead of silently
    returning an empty list."""
    with pytest.raises(psycopg.OperationalError):
        autoclose.load_rules(_BoomConn())


def test_evaluate_fails_open_when_the_rule_cache_reload_raises():
    alert = _alert(severity="medium", agent_name="user1-IA1803")
    ctx = _ctx(
        asset_present=True,
        asset_criticality="medium",
        identity_privileged=False,
        ioc_reputation="not_found",
    )
    decision = autoclose.evaluate(_BoomConn(), alert, ctx, rules=None)
    assert decision == autoclose.AutocloseDecision(blocked_by=None, match=None)


def test_reload_rules_also_fails_open_on_a_dead_connection():
    rules = autoclose.reload_rules(_BoomConn())
    assert rules == []


# ---------------------------------------------------------------------------
# The 60 s cache (design note 4, AC-C4)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_cache_returns_the_same_rules_within_the_ttl(db):
    _seed_user(db)
    decision_before = autoclose.evaluate(db, _alert(), _ctx())  # populates the cache, empty
    assert decision_before.match is None
    _insert_rule(db, rule_id=str(uuid.uuid4()), match=[])
    decision_after = autoclose.evaluate(db, _alert(), _ctx())
    assert decision_after.match is None  # still the cached (empty) list


@pytest.mark.db
def test_cache_reloads_after_the_ttl_elapses(db, monkeypatch):
    _seed_user(db)
    autoclose.evaluate(db, _alert(), _ctx())  # populates the cache, empty
    _insert_rule(db, rule_id=str(uuid.uuid4()), match=[])
    fake_now = time.monotonic() + autoclose.RULE_CACHE_TTL_S + 1
    monkeypatch.setattr(autoclose.time, "monotonic", lambda: fake_now)
    decision = autoclose.evaluate(db, _alert(), _ctx())
    assert decision.match is not None


@pytest.mark.db
def test_reload_rules_busts_the_cache_immediately(db):
    _seed_user(db)
    autoclose.evaluate(db, _alert(), _ctx())  # populates the cache, empty
    _insert_rule(db, rule_id=str(uuid.uuid4()), match=[])
    autoclose.reload_rules(db)
    decision = autoclose.evaluate(db, _alert(), _ctx())
    assert decision.match is not None


# ---------------------------------------------------------------------------
# simulate (acceptance 8)
# ---------------------------------------------------------------------------


def test_simulate_invalid_match_raises_before_touching_the_connection():
    with pytest.raises(PermanentError):
        autoclose.simulate(None, [{"field": "risk_score", "op": "lte", "value": 10}])


@pytest.mark.db
def test_simulate_agrees_with_evaluate(db):
    _seed_user(db)
    closable_asset_ctx = {"present": True, "criticality": "medium"}
    closable_identity_ctx = {"privileged": False}
    closable_ioc_ctx = {"reputation": "not_found"}

    for i in range(3):
        _insert_alert_row(
            db,
            alert_id=f"sim-critical-{i}",
            severity="critical",
            asset_context=closable_asset_ctx,
            identity_context=closable_identity_ctx,
            ioc_context=closable_ioc_ctx,
        )
    for i in range(2):
        _insert_alert_row(
            db,
            alert_id=f"sim-high-asset-{i}",
            severity="high",
            asset_context={"present": True, "criticality": "high"},
            identity_context=closable_identity_ctx,
            ioc_context=closable_ioc_ctx,
        )
    closable_ids = []
    for i in range(7):
        alert_id = f"sim-closable-{i}"
        closable_ids.append(alert_id)
        _insert_alert_row(
            db,
            alert_id=alert_id,
            severity="medium",
            occurrence_count=i + 1,
            asset_context=closable_asset_ctx,
            identity_context=closable_identity_ctx,
            ioc_context=closable_ioc_ctx,
        )

    stats = autoclose.simulate(db, [])
    assert stats.clusters == 7
    assert stats.alerts == sum(range(1, 8))
    assert sum(stats.by_severity.values()) == 7
    assert sum(stats.by_asset_criticality.values()) == 7
    assert len(stats.samples) <= 20
    assert set(stats.samples) <= set(closable_ids)

    _insert_rule(db, rule_id=str(uuid.uuid4()), match=[], name="simulate-match")
    rules = autoclose.load_rules(db)

    scenarios = (
        [(f"sim-critical-{i}", "critical", True, "medium", False, "not_found") for i in range(3)]
        + [(f"sim-high-asset-{i}", "high", True, "high", False, "not_found") for i in range(2)]
        + [(f"sim-closable-{i}", "medium", True, "medium", False, "not_found") for i in range(7)]
    )
    matched = 0
    for alert_id, severity, present, criticality, priv, ioc in scenarios:
        alert = _alert(alert_id=alert_id, severity=severity)
        ctx = _ctx(
            asset_present=present,
            asset_criticality=criticality,
            identity_privileged=priv,
            ioc_reputation=ioc,
        )
        decision = autoclose.evaluate(db, alert, ctx, rules=rules)
        if decision.match is not None:
            matched += 1
    assert matched == 7


@pytest.mark.db
def test_simulate_samples_capped_at_20(db):
    _seed_user(db)
    for i in range(25):
        _insert_alert_row(
            db,
            alert_id=f"cap-{i}",
            severity="medium",
            asset_context={"present": True, "criticality": "medium"},
            identity_context={"privileged": False},
            ioc_context={"reputation": "not_found"},
        )
    stats = autoclose.simulate(db, [])
    assert stats.clusters == 25
    assert stats.alerts == 25
    assert len(stats.samples) == 20


# ---------------------------------------------------------------------------
# Layer 2 — the width report (acceptance 9)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_rule_width_report_sums_occurrence_count_not_rows(db):
    _seed_user(db)
    rule_id = str(uuid.uuid4())
    _insert_rule(db, rule_id=rule_id, match=[], name="wide-rule")
    _insert_alert_row(
        db,
        alert_id="width-big",
        status="auto_closed",
        occurrence_count=5000,
        autoclose_rule_id=rule_id,
    )
    for i in range(100):
        _insert_alert_row(db, alert_id=f"width-other-{i}", status="received", occurrence_count=1)

    cfg = config.load()
    report = autoclose.rule_width_report(db, days=7)
    row = next(r for r in report if r["autoclose_rule_id"] == rule_id)
    assert row["alerts_closed"] == 5000
    assert row["pct"] > cfg.AUTOCLOSE_RULE_WIDTH_PCT


@pytest.mark.db
def test_rule_width_report_below_threshold_is_excluded(db):
    _seed_user(db)
    rule_id = str(uuid.uuid4())
    _insert_rule(db, rule_id=rule_id, match=[], name="narrow-rule")
    _insert_alert_row(
        db,
        alert_id="narrow-1",
        status="auto_closed",
        occurrence_count=1,
        autoclose_rule_id=rule_id,
    )
    for i in range(100):
        _insert_alert_row(db, alert_id=f"narrow-other-{i}", status="received", occurrence_count=1)
    report = autoclose.rule_width_report(db, days=7)
    assert all(r["autoclose_rule_id"] != rule_id for r in report)
