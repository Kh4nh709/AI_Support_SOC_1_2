"""S3 — `queue.get_alert_view` carries the SOAR enrichment as `view["soar"]` (db tests).

The alerts go through the real transitions (`open_alert` → `start_enrichment` →
`finish_enrichment`) from the SOAR team's own samples parsed by `parse_wazuh_alert`, so
`raw_payload` is the alert object exactly as the pipeline stores it. The blob is SIEM context,
not a ① output: it stays on the analyst view of both arms, and the labelling page — which must
stay unprimed (DEC-019) — never receives it. Every test runs in the `db` fixture's transaction.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
from datetime import UTC, datetime

import psycopg
import pytest
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import finish_enrichment, open_alert, start_enrichment
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.tier1 import visibility
from app.tier1.queue import get_alert_view

from tests.soar_payloads import edit, mw03, sc03

_counter = itertools.count()

_CONTEXT = AlertContext(
    asset_present=True,
    asset_criticality="medium",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={},
)


def _alert(doc: dict) -> Alert:
    parsed = parse_wazuh_alert(doc).alert
    assert parsed is not None
    alert_id = f"s3-{next(_counter)}"
    return dataclasses.replace(
        parsed,
        alert_id=alert_id,
        event_bucket_hash=hashlib.sha256(alert_id.encode()).hexdigest(),
    )


def _queued(conn: psycopg.Connection, doc: dict, *, suggestion_visible: bool = True) -> str:
    alert = _alert(doc)
    open_alert(conn, alert, kind="received", source="wazuh", suggestion_visible=suggestion_visible)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(conn, alert.alert_id, context=_CONTEXT, risk_score=30, risk_components={})
    return alert.alert_id


def _walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_keys(item)


@pytest.mark.db
def test_mw03_alert_view_has_the_soar_blob_and_the_event_time(db):
    alert_id = _queued(db, mw03())

    view = get_alert_view(db, alert_id)

    assert view is not None
    soar = view["soar"]
    assert soar["case"] == {
        "case_number": 50,
        "thehive_alert_id": "~921656",
        "dedup_key": "MW03|Windows_Endpoint|Virus:DOS/EICAR_Test_File|20261016-03",
        "case_id": "~42700976",
    }
    assert soar["action"] == {
        "type": "none",
        "target": "Windows_Endpoint",
        "tier": "approval",
        "mode": "act_first",
    }
    assert soar["scenario"] == {"id": "MW03", "name": "Microsoft Defender malware detection"}
    assert soar["triage"]["score"] == 60
    assert soar["triage"]["signal_codes"] == [
        "defender_detection",
        "defender_remediation_succeeded",
    ]
    assert soar["history"]["rule_7d_total"] == 0 and soar["history"]["first_seen_host"] is True
    assert "scan" not in soar and "geo" not in soar and "ti" not in soar
    # The raw payload itself never leaves the reader; only the derived blob does.
    assert "raw_payload" not in view and "enrichment" not in view
    # S4's event_time (timing.event_time) is in the view, next to alert_time.
    assert view["event_time"] == datetime(2026, 10, 15, 20, 25, 22, 355000, tzinfo=UTC)
    assert isinstance(view["alert_time"], datetime)


@pytest.mark.db
def test_sc03_alert_view_has_the_scan_with_previous_output_and_ti(db):
    alert_id = _queued(db, sc03())

    soar = get_alert_view(db, alert_id)["soar"]

    assert soar["action"]["type"] == "block_ip" and soar["action"]["target"] == "79.79.78.202"
    assert soar["scenario"]["id"] == "SC03"
    assert soar["history"]["last_seen"] == "2026-10-16T18:13:31.570Z"
    scan = soar["scan"]
    assert scan["sampled_packets"] == 300 and scan["distinct_dst_ports_sampled"] == 180
    assert len(scan["ports_sampled"]) == 50 and scan["dst_ips"] == ["79.79.78.75"]
    assert scan["actions"] == ["block"]
    assert scan["previous_output"].startswith("filterlog[21588]:")
    assert soar["ti"] == [{"type": "ip", "value": "79.79.78.202", "verdict": "clean"}]


@pytest.mark.db
def test_a_null_case_number_is_kept_in_the_view(db):
    doc = edit(mw03(), "enrichment.case.case_number", None)
    alert_id = _queued(db, doc)

    case = get_alert_view(db, alert_id)["soar"]["case"]

    assert "case_number" in case and case["case_number"] is None
    assert case["thehive_alert_id"] == "~921656"


@pytest.mark.db
def test_an_alert_with_no_enrichment_has_soar_none_and_still_an_event_time(db):
    doc = mw03()
    del doc["enrichment"]
    alert_id = _queued(db, doc)

    view = get_alert_view(db, alert_id)

    assert "soar" in view and view["soar"] is None
    assert view["event_time"] is not None  # timing.event_time is stored whatever the enrichment


@pytest.mark.db
def test_a_hostile_or_malformed_enrichment_never_breaks_the_view(db):
    for enrichment in ([1, 2], "x", 7, {"case": [1], "triage": "x", "evidence": 5, "ti": {"a": 1}}):
        doc = mw03()
        doc["enrichment"] = enrichment
        alert_id = _queued(db, doc)

        view = get_alert_view(db, alert_id)

        assert view is not None and view["soar"] is None, enrichment


@pytest.mark.db
def test_labeling_mode_strips_soar(db):
    alert_id = _queued(db, sc03())

    labeling = get_alert_view(db, alert_id, mode="labeling")
    analyst = get_alert_view(db, alert_id)

    assert labeling is not None
    assert "soar" not in labeling
    assert "soar" not in set(_walk_keys(labeling))
    # The control: the same head's analyst view carries it.
    assert analyst["soar"]["action"]["type"] == "block_ip"


@pytest.mark.db
def test_a_blind_undecided_row_keeps_soar_but_not_the_suggestion_or_triage_status(db):
    visible_id = _queued(db, sc03(), suggestion_visible=True)
    blind_id = _queued(db, sc03(), suggestion_visible=False)

    blind = get_alert_view(db, blind_id)
    visible = get_alert_view(db, visible_id)

    assert blind is not None and visible is not None
    assert blind["suggestion_visible"] is False
    assert blind["soar"] is not None and blind["soar"] == visible["soar"]
    assert visibility.ANALYST_HIDE.isdisjoint(blind)
    assert "suggestion" not in blind and "triage_status" not in blind
    assert "triage_status" in visible  # the control: the visible arm has it


@pytest.mark.db
def test_a_duplicate_resolves_to_its_heads_soar(db):
    head_id = _queued(db, sc03())
    dup = _alert(mw03())  # a different payload: its own enrichment must not be shown
    open_alert(
        db, dup, kind="duplicate", source="wazuh", suggestion_visible=True, duplicate_of=head_id
    )

    view = get_alert_view(db, dup.alert_id)

    assert view["alert_id"] == head_id and view["requested_alert_id"] == dup.alert_id
    assert view["soar"]["scenario"]["id"] == "SC03"


def test_the_soar_key_is_a_labeling_deny_key_and_not_an_analyst_hide_key():
    """Both facts the page relies on, pinned without a database: the labeller is never primed by
    SIEM context, and the blind arm still gets it (it says nothing about ①)."""
    assert "soar" in visibility.LABELING_DENYLIST
    assert "soar" not in visibility.ANALYST_HIDE
    stripped = visibility.strip(
        {"alert_id": "a", "soar": {"case": {"case_number": 1}}, "description": "d"},
        status="queued_tier1",
        suggestion_visible=True,
        mode="labeling",
    )
    assert stripped == {"alert_id": "a", "description": "d"}
