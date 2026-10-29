"""S3 — `app.tier1.soar_view.soar_view`: the SOAR enrichment as one display blob (no database).

Read side only. The input is the alert's `raw_payload->'enrichment'` and its top-level
`previous_output`, both of which are untrusted SIEM free text: the builder keeps what it knows
the type of, bounds every string and list, and drops anything else — it must never raise, and
it must never hand the page a nested object it did not ask for. The shapes below are the SOAR
team's two real samples (`fixtures/soar_payload_sample_1.0.json` for MW03, `..._sc03_1.0.json`
for SC03); `enrichment.geo` is in neither, so its test uses the Owner's field list.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from app.tier1 import soar_view as sv
from app.tier1.soar_view import soar_view

from tests.soar_payloads import edit, mw03, sc03

APP_DIR = Path(__file__).resolve().parents[1] / "app"


def _blob(doc: dict) -> dict | None:
    return soar_view(doc.get("enrichment"), doc.get("previous_output"))


def test_mw03_gives_case_action_scenario_triage_and_history_only():
    blob = _blob(mw03())

    assert blob is not None
    assert blob["case"] == {
        "case_number": 50,
        "thehive_alert_id": "~921656",
        "dedup_key": "MW03|Windows_Endpoint|Virus:DOS/EICAR_Test_File|20261016-03",
        "case_id": "~42700976",
    }
    assert blob["action"] == {
        "type": "none",
        "target": "Windows_Endpoint",
        "tier": "approval",
        "mode": "act_first",
    }
    assert blob["scenario"] == {"id": "MW03", "name": "Microsoft Defender malware detection"}
    assert blob["triage"] == {
        "score": 60,
        "signal_text": (
            "Defender detected Virus:DOS/EICAR_Test_File (Severe, Virus) via Real-Time "
            "Protection; remediation succeeded"
        ),
        "signal_codes": ["defender_detection", "defender_remediation_succeeded"],
    }
    # `last_seen` is null in the sample: a null is absent, not a key with nothing in it.
    assert blob["history"] == {
        "rule_7d_total": 0,
        "rule_7d_host": 0,
        "rule_7d_hosts": 0,
        "first_seen_host": True,
    }
    # Present-only: MW03 carries no geo, no scan, no ti, and the blob does not invent them.
    assert set(blob) == {"case", "action", "scenario", "triage", "history"}


def test_sc03_adds_the_scan_with_previous_output_and_the_ti_list():
    doc = sc03()
    blob = _blob(doc)

    assert blob is not None
    assert blob["action"] == {
        "type": "block_ip",
        "target": "79.79.78.202",
        "tier": "auto",
        "mode": "act_first",
    }
    assert blob["history"]["last_seen"] == "2026-10-16T18:13:31.570Z"
    assert blob["history"]["first_seen_host"] is False
    scan = blob["scan"]
    assert scan["sampled_packets"] == 300
    assert scan["distinct_dst_ports_sampled"] == 180
    assert scan["ports_sampled"] == doc["enrichment"]["evidence"]["scan"]["ports_sampled"]
    assert scan["dst_ips"] == ["79.79.78.75"]
    assert scan["actions"] == ["block"]
    assert scan["previous_output"].startswith("filterlog[21588]: 1,6,,1000000103,em1,match,block")
    assert scan["previous_output_truncated"] is False
    assert blob["ti"] == [{"type": "ip", "value": "79.79.78.202", "verdict": "clean"}]
    assert "geo" not in blob


def test_a_null_case_number_is_kept_as_null():
    """SOAR score < 40: no TheHive case. The page says so, so the key stays and is None."""
    blob = _blob(edit(mw03(), "enrichment.case.case_number", None))

    assert blob is not None
    assert "case_number" in blob["case"] and blob["case"]["case_number"] is None
    assert blob["case"]["dedup_key"].startswith("MW03|")


def test_geo_is_passed_through_present_only_with_scalar_values():
    doc = mw03()
    doc["enrichment"]["geo"] = {
        "country": "VN",
        "country_simulated": True,
        "src_ip_type": "external",
        "first_seen_country_30d": False,
        "seen_count_30d": 3,
        "prior_failures_30m": 12,
        "impossible_travel": False,
        "off_hours": True,
        "surprise": "not on the Owner's list",
        "nested": {"a": 1},
    }

    geo = _blob(doc)["geo"]

    assert geo == {
        "country": "VN",
        "country_simulated": True,
        "src_ip_type": "external",
        "first_seen_country_30d": False,
        "seen_count_30d": 3,
        "prior_failures_30m": 12,
        "impossible_travel": False,
        "off_hours": True,
    }

    doc["enrichment"]["geo"] = {"country": "VN", "src_ip_type": None, "off_hours": {"x": 1}}
    assert _blob(doc)["geo"] == {"country": "VN"}
    doc["enrichment"]["geo"] = {}
    assert "geo" not in _blob(doc)
    doc["enrichment"]["geo"] = "not a block"
    assert "geo" not in _blob(doc)


@pytest.mark.parametrize(
    "enrichment",
    [
        None,
        {},
        [],
        "enrichment",
        42,
        {"schema_version": "1.0"},
        {"asset": {"host": "x"}, "evidence": {"context_logs": []}},  # known, but nothing to show
        {"case": None, "soar": None, "triage": None, "scenario": [], "history": "x"},
    ],
)
def test_no_displayable_enrichment_is_none(enrichment):
    assert soar_view(enrichment, None) is None


def test_previous_output_alone_still_makes_a_scan_blob():
    blob = soar_view({"schema_version": "1.0"}, "filterlog[1]: a\nfilterlog[2]: b")

    assert blob == {
        "scan": {
            "previous_output": "filterlog[1]: a\nfilterlog[2]: b",
            "previous_output_truncated": False,
        }
    }


def test_wrong_types_are_dropped_and_never_raise():
    doc = mw03()
    doc["enrichment"]["case"] = {
        "case_number": True,  # a bool is not a number
        "thehive_alert_id": {"$ne": 1},
        "dedup_key": ["a"],
        "case_id": 7,  # a number where a string was, shown as text
    }
    doc["enrichment"]["soar"] = {"planned_action": "block_ip"}
    doc["enrichment"]["scenario"] = {"id": None, "name": 3.5}
    doc["enrichment"]["triage"] = {
        "score": "60",
        "signal_text": {"a": 1},
        "signal_codes": "x",
    }
    doc["enrichment"]["history"] = {
        "rule_7d_total": "4",
        "rule_7d_host": True,
        "rule_7d_hosts": 1.5,
        "last_seen": 20261016,
        "first_seen_host": "yes",
    }

    blob = _blob(doc)

    assert blob == {
        "case": {"case_id": "7"},
        "scenario": {"name": "3.5"},
        "history": {"rule_7d_hosts": 1.5},
    }


def test_every_string_is_bounded():
    long = "A" * (sv.MAX_TEXT + 500)
    doc = mw03()
    doc["enrichment"]["triage"]["signal_text"] = long
    doc["enrichment"]["scenario"]["name"] = long
    doc["enrichment"]["case"]["dedup_key"] = long

    blob = _blob(doc)

    assert len(blob["triage"]["signal_text"]) == sv.MAX_TEXT
    assert len(blob["scenario"]["name"]) == sv.MAX_TEXT
    assert len(blob["case"]["dedup_key"]) == sv.MAX_TEXT


def test_the_lists_are_bounded_and_the_scan_says_how_many_it_cut():
    doc = sc03()
    scan = doc["enrichment"]["evidence"]["scan"]
    scan["ports_sampled"] = [str(n) for n in range(sv.MAX_PORTS + 40)]
    scan["dst_ips"] = [f"10.0.0.{n % 250}" for n in range(sv.MAX_IPS + 5)]
    scan["actions"] = ["block"] * (sv.MAX_ACTIONS + 5)
    doc["enrichment"]["triage"]["signal_codes"] = ["c"] * (sv.MAX_CODES + 5)
    doc["enrichment"]["ti"] = [
        {"type": "ip", "value": f"1.1.1.{n % 250}", "verdict": "clean"}
        for n in range(sv.MAX_TI + 5)
    ]

    blob = _blob(doc)

    assert len(blob["scan"]["ports_sampled"]) == sv.MAX_PORTS
    assert blob["scan"]["ports_total"] == sv.MAX_PORTS + 40
    assert len(blob["scan"]["dst_ips"]) == sv.MAX_IPS
    assert len(blob["scan"]["actions"]) == sv.MAX_ACTIONS
    assert len(blob["triage"]["signal_codes"]) == sv.MAX_CODES
    assert len(blob["ti"]) == sv.MAX_TI


def test_list_items_of_the_wrong_type_are_skipped():
    doc = sc03()
    doc["enrichment"]["evidence"]["scan"]["ports_sampled"] = ["22", 80, None, {"a": 1}, ["x"], True]
    doc["enrichment"]["evidence"]["scan"]["dst_ips"] = "not a list"
    doc["enrichment"]["ti"] = [
        "x",
        None,
        {"type": "ip", "value": "1.2.3.4", "verdict": "malicious", "looked_up": True},
        {"value": {"a": 1}},
        {},
    ]

    blob = _blob(doc)

    # Numbers are shown as text; a bool, null, object or list is not a port.
    assert blob["scan"]["ports_sampled"] == ["22", "80"]
    assert "dst_ips" not in blob["scan"]
    assert blob["ti"] == [{"type": "ip", "value": "1.2.3.4", "verdict": "malicious"}]


def test_previous_output_is_cut_on_a_line_boundary_and_flagged():
    line = "filterlog[1]: " + "x" * 100
    lines = [line] * 200  # ~23 kB

    blob = soar_view({"scenario": {"id": "SC03"}}, "\n".join(lines))

    shown = blob["scan"]["previous_output"]
    assert len(shown) <= sv.MAX_PREVIOUS_OUTPUT
    assert shown.endswith("x")  # a whole line, not a cut one
    assert set(shown.split("\n")) == {line}
    assert blob["scan"]["previous_output_truncated"] is True
    assert blob["scan"]["previous_output_lines"] == 200

    # A single line longer than the bound is cut, never dropped to nothing.
    blob = soar_view({"scenario": {"id": "SC03"}}, "y" * (sv.MAX_PREVIOUS_OUTPUT + 100))
    assert blob["scan"]["previous_output"] == "y" * sv.MAX_PREVIOUS_OUTPUT
    assert blob["scan"]["previous_output_truncated"] is True

    # Blank or non-text previous_output is no previous_output.
    for empty in ("", "   \n  ", None, 5, ["a"], {"a": 1}):
        assert soar_view({"scenario": {"id": "SC03"}}, empty) == {"scenario": {"id": "SC03"}}


def test_hostile_text_is_kept_as_inert_text_not_interpreted():
    """The builder does not strip or escape: the contract is that the page renders text nodes.
    What it does is make sure the value stays a plain string, bounded."""
    hostile = '<img src=x onerror="alert(1)"></script><script>alert(2)</script>'
    doc = mw03()
    doc["enrichment"]["triage"]["signal_text"] = hostile
    doc["enrichment"]["scenario"]["name"] = hostile

    blob = _blob(doc)

    assert blob["triage"]["signal_text"] == hostile
    assert blob["scenario"]["name"] == hostile
    assert isinstance(blob["scenario"]["name"], str)


def test_the_input_is_never_mutated():
    doc = sc03()
    before = copy.deepcopy(doc)

    _blob(doc)

    assert doc == before


def test_the_result_is_json_native():
    import json

    blob = _blob(sc03())

    assert json.loads(json.dumps(blob)) == blob


def test_it_is_read_side_only_no_gate_fact_or_llm_path_imports_it():
    """DEC-025 / the card: the SIEM's score and verdict are shown, never used. Nothing under
    `llm/`, `security/`, `soar/` or the triage job may import this module."""
    offenders = []
    for folder in ("llm", "security", "soar"):
        for path in sorted((APP_DIR / folder).rglob("*.py")):
            if "soar_view" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(APP_DIR)))
    triage = (APP_DIR / "tier1" / "triage.py").read_text(encoding="utf-8")
    if "soar_view" in triage:
        offenders.append("tier1/triage.py")
    assert offenders == []
