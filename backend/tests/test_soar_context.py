"""P12-T02 / DEC-208 (as amended 23/10) — a SOAR payload's `enrichment` block becomes the alert's `AlertContext`.

With `ENRICHMENT_ENABLED=false` the pipeline looks nothing up (P12-T01); the context now comes from
the document itself, from `enrichment` (schema `1.x`) that SOAR/n8n added to the Wazuh-shaped alert:

- `asset_criticality` = `asset.criticality`, `asset_present` = `asset.in_inventory` (the earlier
  `asset.critical` is SOAR's own scoring flag and is not read);
- `identity_privileged` = `asset.user_is_admin`, `None` (identity `skipped`) when it is `null`, absent,
  or when the alert names no account;
- `ioc_reputation` = the worst of `ti[].verdict` and `ioc.verdict`; no block is `skipped`;
- any value outside its vocabulary, or of the wrong type, makes the WHOLE context the "unknown" one
  (DEC-208 item 3: a half-trusted context is not built), and the log names the field, never the value.

The two real samples the SOAR team sent are copied under `fixtures/` (`soar_payload_sample_1.0.json`,
a Defender alert of scenario MW03, sent before `in_inventory`/`criticality` existed;
`soar_payload_sample_sc03_1.0.json`, a pfSense port scan, the current shape). The variants are derived
from them here. The expected contexts are written out literally, not computed by the code under test.

Part 1 is pure: `_build_context` is handed a connection that fails on any use, which is also the proof
that no statement reaches `assets`, `identities` or `iocs`. Part 2 runs both samples through
`intake.receive` and `run_pipeline_job` on the test database, with the four switches off.
"""

from __future__ import annotations

import copy
import dataclasses
import logging
import re

import psycopg
import pytest
from app.domain.alert import AlertContext
from app.infra import config
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.soar import pipeline

from tests.soar_payloads import MISSING as _MISSING
from tests.soar_payloads import SWITCHES, edit, mw03, receive_and_run, sc03, stream_config, ti

#: The "unknown" context of DEC-207 item 1, written out: nothing is claimed about the asset, the
#: account or the addresses, and the gate reads every one of these as "not a pass".
UNKNOWN = AlertContext(
    False,
    "unknown",
    None,
    None,
    None,
    "skipped",
    {"asset": "skipped", "identity": "skipped", "ioc": "skipped"},
)
OFF = dataclasses.replace(config.Config(), ENRICHMENT_ENABLED=False)


class NoConnection:
    """Stands in for the database connection: the SOAR branch must never touch it."""

    def __getattr__(self, name: str):
        raise AssertionError(
            f"the connection was used (.{name}) although the context is the payload's"
        )


def parsed(doc: dict):
    result = parse_wazuh_alert(copy.deepcopy(doc))
    assert result.alert is not None, result.rejection
    return result.alert


def context_of(doc: dict) -> AlertContext:
    return pipeline._build_context(NoConnection(), parsed(doc), cfg=OFF)


# ---------------------------------------------------------------------------
# 1 · the mapping, on the two real samples
# ---------------------------------------------------------------------------


def test_mw03_with_the_two_new_asset_fields_is_medium_unprivileged_and_unchecked() -> None:
    ctx = context_of(mw03(criticality="medium", in_inventory=True))

    assert ctx == AlertContext(
        True,
        "medium",
        None,
        None,
        False,
        "skipped",
        {"asset": "found", "identity": "found", "ioc": "skipped"},
    )


def test_mw03_as_first_sent_has_no_criticality_and_is_not_known_to_the_inventory() -> None:
    """The sample predates `in_inventory` and `criticality`: the asset is `unknown` and absent for
    that field only; the account is still read (`user_is_admin: false`) and so is the missing IoC.
    """
    ctx = context_of(mw03())

    assert ctx == AlertContext(
        False,
        "unknown",
        None,
        None,
        False,
        "skipped",
        {"asset": "skipped", "identity": "found", "ioc": "skipped"},
    )


def test_sc03_is_high_with_no_account_and_a_clean_address() -> None:
    ctx = context_of(sc03())

    assert ctx == AlertContext(
        True,
        "high",
        None,
        None,
        None,
        "clean",
        {"asset": "found", "identity": "skipped", "ioc": "found"},
    )


def test_sc03_parses_as_the_brief_checked_it() -> None:
    alert = parsed(sc03())

    assert alert.category == "recon"  # by MITRE T1046, there being no `pf` decoder entry
    assert alert.srcip == "79.79.78.202" and alert.dstip == "79.79.78.75"
    assert (alert.src_port, alert.dst_port) == (48509, 993)
    assert alert.raw_log == sc03()["full_log"] and alert.raw_log.startswith("<134>Oct 16")
    assert alert.alert_user is None  # the sample names no account


@pytest.mark.parametrize("verdict", ["malicious", "suspicious", "clean"])
def test_each_ti_verdict_is_the_ioc_reputation(verdict: str) -> None:
    ctx = context_of(edit(sc03(), "enrichment.ti", [ti(verdict)]))

    assert ctx.ioc_reputation == verdict
    assert dict(ctx.lookup_status)["ioc"] == "found"


@pytest.mark.parametrize(
    "verdicts, worst",
    [
        (["clean", "malicious"], "malicious"),
        (["malicious", "clean"], "malicious"),
        (["clean", "suspicious"], "suspicious"),
        (["suspicious", "clean"], "suspicious"),
        (["suspicious", "malicious"], "malicious"),
        (["malicious", "suspicious"], "malicious"),
        (["clean", "suspicious", "malicious", "clean"], "malicious"),
        (["clean", "clean"], "clean"),
    ],
)
def test_several_ti_entries_take_the_worst_verdict(verdicts: list[str], worst: str) -> None:
    ctx = context_of(edit(sc03(), "enrichment.ti", [ti(v) for v in verdicts]))

    assert ctx.ioc_reputation == worst


@pytest.mark.parametrize("verdict", ["malicious", "suspicious", "clean"])
def test_the_c202_ioc_block_is_read_without_any_ti_entry(verdict: str) -> None:
    doc = edit(sc03(), "enrichment.ti")
    edit(doc, "enrichment.ioc", {"verdict": verdict})

    ctx = context_of(doc)

    assert ctx.ioc_reputation == verdict
    assert dict(ctx.lookup_status)["ioc"] == "found"


@pytest.mark.parametrize(
    "ti_verdict, ioc_verdict, worst",
    [
        ("clean", "malicious", "malicious"),
        ("malicious", "clean", "malicious"),
        ("clean", "suspicious", "suspicious"),
        ("suspicious", "clean", "suspicious"),
        ("clean", "clean", "clean"),
    ],
)
def test_ti_and_the_ioc_block_together_take_the_worst(
    ti_verdict: str, ioc_verdict: str, worst: str
) -> None:
    doc = edit(sc03(), "enrichment.ti", [ti(ti_verdict)])
    edit(doc, "enrichment.ioc", {"verdict": ioc_verdict})

    assert context_of(doc).ioc_reputation == worst


@pytest.mark.parametrize("block", [_MISSING, None, []], ids=["absent", "null", "empty list"])
def test_no_ti_block_and_no_ioc_block_is_skipped_not_clean(block: object) -> None:
    doc = sc03()
    if block is _MISSING:
        edit(doc, "enrichment.ti")
    else:
        edit(doc, "enrichment.ti", block)

    ctx = context_of(doc)

    assert ctx.ioc_reputation == "skipped"
    assert dict(ctx.lookup_status)["ioc"] == "skipped"


def test_a_null_ioc_block_is_no_block() -> None:
    ctx = context_of(edit(edit(sc03(), "enrichment.ti"), "enrichment.ioc", None))

    assert ctx.ioc_reputation == "skipped"


@pytest.mark.parametrize("criticality", ["high", "medium", "low", "unknown"])
def test_each_criticality_of_the_vocabulary_is_read(criticality: str) -> None:
    ctx = context_of(edit(sc03(), "enrichment.asset.criticality", criticality))

    assert ctx.asset_criticality == criticality


def test_an_absent_criticality_is_unknown_for_that_field_only() -> None:
    ctx = context_of(
        edit(edit(sc03(), "enrichment.asset.criticality"), "enrichment.ti", [ti("malicious")])
    )

    assert ctx.asset_criticality == "unknown"
    assert ctx.ioc_reputation == "malicious"  # the rest of the block is still trusted


def test_a_host_outside_the_inventory_is_absent_and_not_found() -> None:
    ctx = context_of(edit(sc03(), "enrichment.asset.in_inventory", False))

    assert ctx.asset_present is False
    assert dict(ctx.lookup_status)["asset"] == "not_found"


@pytest.mark.parametrize("value", [True, False, "yes", None, 5, ""])
def test_asset_critical_is_not_read(value: object) -> None:
    """SOAR's own scoring flag (true only for its critical list): neither `high` nor an error."""
    baseline = context_of(sc03())

    assert context_of(edit(sc03(), "enrichment.asset.critical", value)) == baseline
    assert (
        context_of(
            edit(mw03(criticality="low", in_inventory=True), "enrichment.asset.critical", value)
        ).asset_criticality
        == "low"
    )


@pytest.mark.parametrize("value", [True, "yes"])
def test_asset_critical_never_makes_an_asset_high(value: object) -> None:
    """The earlier mapping (`critical: true` -> `high`) is gone: with no `criticality` the asset is
    `unknown` whatever SOAR's scoring flag says, and the gate keeps reading it as a block."""
    doc = edit(edit(sc03(), "enrichment.asset.criticality"), "enrichment.asset.critical", value)

    assert context_of(doc).asset_criticality == "unknown"


def test_the_host_name_is_not_what_decides_presence() -> None:
    doc = edit(sc03(), "enrichment.asset.host", "")
    assert context_of(doc).asset_present is True  # `in_inventory` says so


@pytest.mark.parametrize(
    "user, is_admin, privileged, identity",
    [
        ("FPT\\hr01", False, False, "found"),
        ("FPT\\hr01", True, True, "found"),
        ("hr01", True, True, "found"),
        ("FPT\\hr01", None, None, "skipped"),
        ("FPT\\hr01", _MISSING, None, "skipped"),
        (None, False, None, "skipped"),  # SC03: no account, so nothing was looked up
        (None, True, None, "skipped"),
        (_MISSING, True, None, "skipped"),
        ("", True, None, "skipped"),
        ("   ", False, None, "skipped"),
    ],
)
def test_the_account_is_read_only_when_the_alert_names_one(
    user: object, is_admin: object, privileged: bool | None, identity: str
) -> None:
    doc = sc03()
    for key, value in (("user", user), ("user_is_admin", is_admin)):
        if value is _MISSING:
            edit(doc, f"enrichment.asset.{key}")
        else:
            edit(doc, f"enrichment.asset.{key}", value)

    ctx = context_of(doc)

    assert ctx.identity_privileged is privileged
    assert dict(ctx.lookup_status)["identity"] == identity


@pytest.mark.parametrize("asset", [_MISSING, None, {}], ids=["absent", "null", "empty"])
def test_no_asset_block_is_an_unknown_asset_and_not_an_invalid_payload(asset: object) -> None:
    """An absent block is absent, not wrong: the asset and the account are unknown, and the address
    verdicts of the same payload are still read."""
    doc = sc03()
    if asset is _MISSING:
        edit(doc, "enrichment.asset")
    else:
        edit(doc, "enrichment.asset", asset)

    assert context_of(doc) == AlertContext(
        False,
        "unknown",
        None,
        None,
        None,
        "clean",
        {"asset": "skipped", "identity": "skipped", "ioc": "found"},
    )


def test_nothing_is_looked_up_and_owner_and_role_stay_empty() -> None:
    ctx = context_of(mw03(criticality="medium", in_inventory=True))

    assert ctx.asset_owner is None and ctx.asset_role is None


# ---------------------------------------------------------------------------
# 1b · anything outside the vocabulary, or of the wrong type: the whole context is "unknown"
# ---------------------------------------------------------------------------

#: `(label, dotted path, value)`; `_MISSING` removes the key. Each is applied to SC03 carrying a
#: `malicious` TI entry and `criticality: high`, i.e. to a document whose valid context would NOT
#: be the unknown one: the assertion that it is, is therefore the whole-context rule and not just
#: the field's own default.
_INVALID = [
    ("ti verdict outside the vocabulary", "enrichment.ti", [ti("bad")]),
    ("ti verdict in capitals", "enrichment.ti", [ti("MALICIOUS")]),
    ("ti verdict not_found", "enrichment.ti", [ti("not_found")]),
    ("ti verdict unknown", "enrichment.ti", [ti("unknown")]),
    ("ti verdict empty", "enrichment.ti", [ti("")]),
    ("ti verdict null", "enrichment.ti", [ti(None)]),
    ("ti verdict a number", "enrichment.ti", [ti(1)]),
    ("ti verdict a bool", "enrichment.ti", [ti(True)]),
    ("ti verdict a list", "enrichment.ti", [ti(["malicious"])]),
    ("ti entry without a verdict", "enrichment.ti", [{"type": "ip", "looked_up": True}]),
    ("one good and one bad ti entry", "enrichment.ti", [ti("malicious"), ti("bad")]),
    ("one bad and one good ti entry", "enrichment.ti", [ti("bad"), ti("malicious")]),
    ("ti entry a string", "enrichment.ti", ["malicious"]),
    ("ti entry null", "enrichment.ti", [None]),
    ("ti an object", "enrichment.ti", {"verdict": "malicious"}),
    ("ti a string", "enrichment.ti", "malicious"),
    ("ioc verdict outside the vocabulary", "enrichment.ioc", {"verdict": "bad"}),
    ("ioc verdict a number", "enrichment.ioc", {"verdict": 2}),
    ("ioc without a verdict", "enrichment.ioc", {}),
    ("ioc a string", "enrichment.ioc", "malicious"),
    ("ioc a list", "enrichment.ioc", [{"verdict": "malicious"}]),
    ("criticality a string outside the four", "enrichment.asset.criticality", "critical"),
    ("criticality in capitals", "enrichment.asset.criticality", "HIGH"),
    ("criticality empty", "enrichment.asset.criticality", ""),
    ("criticality null", "enrichment.asset.criticality", None),
    ("criticality a number", "enrichment.asset.criticality", 3),
    ("criticality a bool", "enrichment.asset.criticality", True),
    ("criticality a list", "enrichment.asset.criticality", ["high"]),
    ("criticality an object", "enrichment.asset.criticality", {"level": "high"}),
    ("in_inventory a string", "enrichment.asset.in_inventory", "true"),
    ("in_inventory a number", "enrichment.asset.in_inventory", 1),
    ("in_inventory null", "enrichment.asset.in_inventory", None),
    ("user_is_admin a string", "enrichment.asset.user_is_admin", "yes"),
    ("user_is_admin a number", "enrichment.asset.user_is_admin", 1),
    ("user a number", "enrichment.asset.user", 5),
    ("user a list", "enrichment.asset.user", ["FPT\\hr01"]),
    ("asset a string", "enrichment.asset", "high"),
    ("asset a list", "enrichment.asset", []),
    ("schema 2.0", "enrichment.schema_version", "2.0"),
    ("schema 10.0", "enrichment.schema_version", "10.0"),
    ("schema 1", "enrichment.schema_version", "1"),
    ("schema 1.", "enrichment.schema_version", "1."),
    ("schema 1.0.1", "enrichment.schema_version", "1.0.1"),
    ("schema 1.x", "enrichment.schema_version", "1.x"),
    ("schema v1.0", "enrichment.schema_version", "v1.0"),
    ("schema padded", "enrichment.schema_version", " 1.0"),
    ("schema a float", "enrichment.schema_version", 1.0),
    ("schema an int", "enrichment.schema_version", 1),
    ("schema null", "enrichment.schema_version", None),
    ("schema missing", "enrichment.schema_version", _MISSING),
    ("enrichment missing", "enrichment", _MISSING),
    ("enrichment null", "enrichment", None),
    ("enrichment a string", "enrichment", "1.0"),
    ("enrichment a list", "enrichment", []),
]


def _valid_and_loud() -> dict:
    """SC03 with a `malicious` TI entry: its valid context is `high` / `malicious`."""
    return edit(sc03(), "enrichment.ti", [ti("malicious")])


def test_the_document_the_invalid_cases_start_from_is_not_the_unknown_context() -> None:
    """The control (DEC-025): without a mutation the context is the real one, so each case below
    differs from it by that field alone."""
    ctx = context_of(_valid_and_loud())

    assert (ctx.asset_criticality, ctx.ioc_reputation) == ("high", "malicious")
    assert ctx != UNKNOWN


@pytest.mark.parametrize("path, value", [pytest.param(p, v, id=label) for label, p, v in _INVALID])
def test_a_value_outside_its_vocabulary_or_of_the_wrong_type_makes_the_whole_context_unknown(
    path: str, value: object
) -> None:
    doc = _valid_and_loud()
    if value is _MISSING:
        edit(doc, path)
    else:
        edit(doc, path, value)

    assert context_of(doc) == UNKNOWN


@pytest.mark.parametrize(
    "path, secret, field",
    [
        ("enrichment.asset.criticality", "SECRET-crit-7f3a", "enrichment.asset.criticality"),
        ("enrichment.asset.in_inventory", "SECRET-inv-91bc", "enrichment.asset.in_inventory"),
        ("enrichment.asset.user_is_admin", "SECRET-adm-22de", "enrichment.asset.user_is_admin"),
        ("enrichment.asset.user", ["SECRET-usr-5a60"], "enrichment.asset.user"),
        ("enrichment.schema_version", "SECRET-ver-0c11", "enrichment.schema_version"),
        ("enrichment.ti", [ti("SECRET-ti-48e9")], "enrichment.ti[].verdict"),
        ("enrichment.ioc", {"verdict": "SECRET-ioc-b3d7"}, "enrichment.ioc.verdict"),
    ],
)
def test_the_log_names_the_field_and_never_its_value(
    path: str, secret: object, field: str, caplog: pytest.LogCaptureFixture
) -> None:
    doc = edit(_valid_and_loud(), path, secret)

    with caplog.at_level(logging.DEBUG):
        ctx = context_of(doc)

    assert ctx == UNKNOWN
    assert field in caplog.text
    assert "SECRET" not in caplog.text
    assert any(record.levelno >= logging.WARNING for record in caplog.records)
    assert all("SECRET" not in repr(record.args) for record in caplog.records)


def test_a_missing_block_is_logged_by_its_name_too(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        ctx = context_of(edit(sc03(), "enrichment"))

    assert ctx == UNKNOWN
    assert "enrichment" in caplog.text


def test_a_valid_payload_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        context_of(sc03())

    assert caplog.records == []


def test_any_minor_version_of_schema_1_is_read() -> None:
    for version in ("1.0", "1.1", "1.12", "1.100"):
        assert (
            context_of(edit(sc03(), "enrichment.schema_version", version)).asset_criticality
            == "high"
        )


def test_a_payload_wrapped_as_an_indexer_hit_is_read_the_same() -> None:
    """The block lives in the alert object, which is `_source` when the body is a hit."""
    hit = {"_index": "wazuh-alerts-4.x-2026.10.17", "_id": "x", "sort": [1], "_source": sc03()}

    assert context_of(hit) == context_of(sc03())
    assert context_of(hit).asset_criticality == "high"


def test_fields_a_later_1_x_adds_are_ignored() -> None:
    doc = edit(sc03(), "enrichment.future_block", {"verdict": "bad", "criticality": 7})
    edit(doc, "enrichment.asset.future_field", ["x"])

    assert context_of(doc) == context_of(sc03())


# ---------------------------------------------------------------------------
# 1c · the connection is never used, and a run with enrichment ON is the one of before
# ---------------------------------------------------------------------------


def test_no_statement_is_sent_for_a_payload_context() -> None:
    """`NoConnection` fails on any attribute: `context_of` above is the proof, repeated here on the
    one path where a lookup was most likely to be left in (a host name, an account and two
    addresses, all of which the internal lookups would have queried)."""
    doc = mw03(criticality="medium", in_inventory=True)
    alert = parsed(doc)
    assert alert.agent_name and alert.alert_user and alert.origin_host

    assert pipeline._build_context(NoConnection(), alert, cfg=OFF).asset_criticality == "medium"


def test_with_enrichment_on_the_payload_is_not_read_and_the_lookups_run(monkeypatch) -> None:
    """The control of the tests above: the same document, `ENRICHMENT_ENABLED` true. The internal
    lookups run (their statements are recorded), and `criticality: high` of the payload does not
    reach the context."""
    seen: list[str] = []

    def lookup_asset(conn, agent_name, origin_host):
        seen.append("asset")
        return {
            "present": False,
            "criticality": "unknown",
            "owner": None,
            "role": None,
            "status": "not_found",
        }

    def lookup_identity(conn, user):
        seen.append("identity")
        return {"is_privileged": None, "status": "not_found"}

    def lookup_ioc(conn, srcip, dstip, **kwargs):
        seen.append("ioc")
        return {"reputation": "not_found", "status": "not_found"}

    monkeypatch.setattr(pipeline.lookups, "lookup_asset", lookup_asset)
    monkeypatch.setattr(pipeline.lookups, "lookup_identity", lookup_identity)
    monkeypatch.setattr(pipeline.lookups, "lookup_ioc", lookup_ioc)
    on = dataclasses.replace(config.Config(), ENRICHMENT_ENABLED=True)

    ctx = pipeline._build_context(NoConnection(), parsed(sc03()), cfg=on)

    assert seen == ["asset", "identity", "ioc"]
    assert ctx.asset_criticality == "unknown" and ctx.ioc_reputation == "not_found"


# ---------------------------------------------------------------------------
# 2 · through the webhook intake and the pipeline, on the test database
# ---------------------------------------------------------------------------

_LOOKUP_TABLES = re.compile(r"\b(assets|identities|iocs)\b", re.IGNORECASE)


def _statement_text(query, conn) -> str:
    if isinstance(query, bytes):
        return query.decode("utf-8", "replace")
    if hasattr(query, "as_string"):
        return query.as_string(conn)
    return str(query)


@pytest.fixture
def rec(_test_database):
    """`(connection, statements)`: a connection that records the text of every statement sent
    through it (`test_pipeline.py`'s fixture of the same name)."""
    statements: list[str] = []

    class _RecordingCursor(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            statements.append(_statement_text(query, self.connection))
            return super().execute(query, params, **kwargs)

    conn = psycopg.connect(_test_database, cursor_factory=_RecordingCursor)
    try:
        yield conn, statements
    finally:
        conn.rollback()
        conn.close()


_ROW = (
    "status, severity, category, alert_user, raw_log, asset_context, identity_context, "
    "ioc_context, lookup_status, risk_score, risk_score_components, occurrence_count"
)


def _alert_row(conn: psycopg.Connection, alert_id: str) -> dict:
    record = conn.execute(f"SELECT {_ROW} FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
    assert record is not None, alert_id
    return dict(zip(_ROW.replace(" ", "").split(","), record, strict=True))


@pytest.mark.db
def test_the_mw03_sample_through_the_stream_is_a_queued_alert_with_its_payload_context(
    rec, monkeypatch
) -> None:
    conn, log = rec
    cfg = stream_config(monkeypatch)
    doc = mw03(criticality="medium", in_inventory=True)
    log.clear()

    receive_and_run(conn, cfg, doc)

    assert [s for s in log if _LOOKUP_TABLES.search(s)] == []  # not one statement on the inventory
    row = _alert_row(conn, doc["id"])
    assert row["status"] == "queued_tier1"
    assert (row["severity"], row["category"]) == ("critical", "malware")
    assert row["alert_user"] == "hr01"  # the parser's fallback: `FPT\hr01` without its domain
    assert row["asset_context"] == {
        "present": True,
        "criticality": "medium",
        "owner": None,
        "role": None,
    }
    assert row["identity_context"] == {"privileged": False}
    assert row["ioc_context"] == {"reputation": "skipped"}
    assert row["lookup_status"] == {"asset": "found", "identity": "found", "ioc": "skipped"}
    components = row["risk_score_components"]
    assert (components["base"], components["asset"], components["identity"]) == (70, 10, 0)
    assert (components["ioc"], components["occurrence"]) == (0, 0)
    assert row["risk_score"] == 80
    assert (
        row["occurrence_count"] == 1
    )  # the column keeps its default; the facts of ① do not read it


@pytest.mark.db
def test_the_sc03_sample_through_the_stream_scores_the_high_asset(rec, monkeypatch) -> None:
    conn, log = rec
    cfg = stream_config(monkeypatch)
    doc = sc03()
    log.clear()

    receive_and_run(conn, cfg, doc)

    assert [s for s in log if _LOOKUP_TABLES.search(s)] == []
    row = _alert_row(conn, doc["id"])
    assert row["status"] == "queued_tier1"
    assert (row["severity"], row["category"]) == ("high", "recon")
    assert row["raw_log"] == doc["full_log"]
    assert row["alert_user"] is None
    assert row["asset_context"]["criticality"] == "high" and row["asset_context"]["present"] is True
    assert row["identity_context"] == {"privileged": None}
    assert row["ioc_context"] == {"reputation": "clean"}
    assert row["lookup_status"] == {"asset": "found", "identity": "skipped", "ioc": "found"}
    components = row["risk_score_components"]
    assert (components["base"], components["asset"], components["context_capped"]) == (50, 30, 25)
    assert row["risk_score"] == 75


@pytest.mark.db
def test_a_payload_that_is_not_valid_is_queued_with_the_unknown_context(rec, monkeypatch) -> None:
    conn, log = rec
    cfg = stream_config(monkeypatch)
    doc = edit(sc03(), "enrichment.asset.criticality", "critical")
    log.clear()

    receive_and_run(conn, cfg, doc)

    row = _alert_row(conn, doc["id"])
    assert row["status"] == "queued_tier1"  # accepted, as DEC-207 says; read as "unknown"
    assert row["asset_context"] == {
        "present": False,
        "criticality": "unknown",
        "owner": None,
        "role": None,
    }
    assert row["lookup_status"] == {"asset": "skipped", "identity": "skipped", "ioc": "skipped"}
    assert row["risk_score"] == row["risk_score_components"]["base"] == 50


@pytest.mark.db
@pytest.mark.parametrize(
    "make_doc, touched",
    [
        pytest.param(sc03, {"assets", "iocs"}, id="sc03: two addresses, no account"),
        pytest.param(
            lambda: mw03(criticality="medium", in_inventory=True),
            {"assets", "identities"},
            id="mw03: an account, no address",
        ),
    ],
)
def test_with_enrichment_on_a_soar_payload_is_scored_from_the_inventory_and_not_the_payload(
    rec, monkeypatch, make_doc, touched
) -> None:
    """The control of part 2: `ENRICHMENT_ENABLED` unset, the same documents. The internal lookups
    run (each looks up what the alert has: an account, an address; an empty inventory finds nothing,
    `not_found`), and the payload's `high` or `medium` is not used."""
    conn, log = rec
    for name in SWITCHES:
        monkeypatch.delenv(name, raising=False)
    cfg = dataclasses.replace(config.load(env_file="/dev/null"), WEBHOOK_API_KEY="k")
    doc = make_doc()
    log.clear()

    receive_and_run(conn, cfg, doc)

    assert {m.group(1).lower() for s in log for m in _LOOKUP_TABLES.finditer(s)} == touched
    row = _alert_row(conn, doc["id"])
    assert row["asset_context"]["criticality"] == "unknown"  # not the payload's
    assert row["lookup_status"]["asset"] == "not_found"
