"""`ingest/wazuh_parser.py` reads `data.win.*` from a Windows eventchannel alert (P9-T01, DEC-149).

Card: docs/plan/tasks/P9/P9-tasks.md §3. Three parts:

1. **Linux unchanged.** Every Linux document the existing parser tests use is re-parsed
   and compared field by field — `event_bucket_hash` (the dedup key) and `raw_payload`
   included — with `fixtures/linux_parse_snapshot.json`. The corpus is the real fixtures
   under `fixtures/` (the three `test_wazuh_parser.py` loads, the raw archive line inside
   one of them, and the indexer samples, search pages and heartbeat hit that the
   pipeline, label and puller tests parse) plus the inline documents of
   `test_wazuh_parser.py`, copied here verbatim. The snapshot is the **base** parser's
   output: written at ba7b070, before `wazuh_parser.py` was edited, and never
   regenerated — a parser change is proved against it, not written into it.
2. **One case per Windows event type** the card names — 4625 (a network logon failure
   with `ipAddress`), 4624 logon type 10, 4740, Sysmon 1/3/11/22 and Defender 1116 —
   each checking the extracted fields, the empty-value filters and the `raw_log`
   fallback.
3. **No double reading:** a value the Linux shape already gave is kept.
"""

from __future__ import annotations

import copy
import dataclasses
import functools
import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

import pytest
from app.domain.alert import Alert, compute_event_bucket_hash
from app.ingest import category
from app.ingest.wazuh_parser import ParseResult, parse_wazuh_alert

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT = FIXTURES / "linux_parse_snapshot.json"

#: `config.py`'s RAW_LOG_MAX_BYTES default, set explicitly for every case so a
#: developer's `.env` cannot change what the snapshot is compared against.
DEFAULT_RAW_LOG_MAX_BYTES = 1_024_000

_TS = "2026-08-16T17:56:56.130+0000"


# ---------------------------------------------------------------------------
# 1 · Linux unchanged — the corpus, its encoding, and the base snapshot
# ---------------------------------------------------------------------------


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _minimal(**extra) -> dict:
    """The one-alert `_source` that `test_wazuh_parser.py` writes inline again and again."""
    return {
        "_source": {
            "id": "1.1",
            "rule": {"id": "1", "description": "d"},
            "timestamp": _TS,
            **extra,
        }
    }


def _doc_with(mitre_ids=(), groups=(), decoder=None, dst_port=0) -> dict:
    """`test_wazuh_parser.py`'s own `_doc_with`, verbatim."""
    return {
        "_source": {
            "id": "1.1",
            "rule": {
                "id": "1",
                "description": "d",
                "mitre": {"id": list(mitre_ids)},
                "groups": list(groups),
            },
            "timestamp": _TS,
            "decoder": {"name": decoder} if decoder else {},
            "data": {"dstport": dst_port},
        }
    }


def linux_corpus() -> list[tuple[str, dict, int]]:
    """`(case name, document, RAW_LOG_MAX_BYTES)` for every Linux document the existing
    parser tests use, in a fixed order; the snapshot is keyed by these names."""
    default = DEFAULT_RAW_LOG_MAX_BYTES
    canonical = _load("alert_40112.json")
    no_agent = copy.deepcopy(canonical)
    del no_agent["_source"]["agent"]
    level_11 = copy.deepcopy(canonical)
    level_11["_source"]["rule"]["level"] = 11
    archive = _load("archive_line_5503.json")

    cases: list[tuple[str, dict, int]] = [
        ("alert_40112.json", canonical, default),
        ("alert_40112.json without its agent object", no_agent, default),
        ("alert_40112.json with rule.level 11", level_11, default),
        ("indexer_hit_no_fields.json", _load("indexer_hit_no_fields.json"), default),
        ("archive_line_5503.json", archive, default),
        (
            "archive_line_5503.json event.original",
            json.loads(archive["event"]["original"]),
            default,
        ),
        ("indexer_heartbeat_hit.json", _load("indexer_heartbeat_hit.json"), default),
    ]
    for rule_id in ("521", "591", "5503", "5760", "92601"):
        name = f"indexer_sample_rule{rule_id}.json"
        cases.append((name, _load(name), default))
    for page in ("indexer_search_page.json", "indexer_search_page_2.json"):
        for i, hit in enumerate(_load(page)["hits"]["hits"]):
            cases.append((f"{page} hits[{i}]", hit, default))

    # test_wazuh_parser.py's inline documents, verbatim, in that file's order.
    cases += [
        (
            "inline: rule.id missing",
            {"id": "1", "rule": {"description": "x"}, "timestamp": "x"},
            default,
        ),
        (
            "inline: new year's eve predecoder",
            {
                "_source": {
                    "id": "1.1",
                    "rule": {"id": "1", "description": "d"},
                    "predecoder": {"timestamp": "Dec 31 23:59:59"},
                    "timestamp": "2027-01-01T00:00:01+0000",
                }
            },
            default,
        ),
        (
            "inline: garbage predecoder timestamp",
            {
                "_source": {
                    "id": "1.1",
                    "rule": {"id": "1", "description": "d"},
                    "predecoder": {"timestamp": "not-a-time"},
                    "timestamp": _TS,
                }
            },
            default,
        ),
        (
            "inline: no timestamp at all",
            {"id": "1", "rule": {"id": "1", "description": "d"}},
            default,
        ),
    ]
    for bad_port in ("unknown", "", "  48104  ", None):
        cases.append(
            (f"inline: srcport {bad_port!r}", _minimal(data={"srcport": bad_port}), default)
        )
    cases += [
        ("inline: minimal, no data object", _minimal(), default),
        (
            "inline: dstuser and srcuser",
            _minimal(data={"dstuser": "root", "srcuser": "eve"}),
            default,
        ),
        ("inline: srcuser only", _minimal(data={"srcuser": "eve"}), default),
        (
            "inline: empty dstuser, srcuser",
            _minimal(data={"dstuser": "", "srcuser": "eve"}),
            default,
        ),
    ]
    for label, kwargs in (
        ("mitre T1110", {"mitre_ids": ["T1110"]}),
        ("mitre T1110.001", {"mitre_ids": ["T1110.001"]}),
        ("groups authentication_failed", {"groups": ["authentication_failed"]}),
        ("decoder sshd", {"decoder": "sshd"}),
        ("dst_port 22", {"dst_port": 22}),
        ("mitre T1078+T1110", {"mitre_ids": ["T1078", "T1110"]}),
        ("mitre T1110+T1078", {"mitre_ids": ["T1110", "T1078"]}),
        ("no signal", {}),
        ("mitre T1078", {"mitre_ids": ["T1078"]}),
        ("dst_port 80", {"dst_port": 80}),
    ):
        cases.append((f"inline: _doc_with {label}", _doc_with(**kwargs), default))
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.1.1", "8.8.8.8", "not-an-ip"):
        cases.append((f"inline: srcip {ip}", _minimal(data={"srcip": ip}), default))
    cases += [
        ("inline: full_log 50 bytes, limit 20", _minimal(full_log="x" * 50), 20),
        ("inline: full_log 'é'*7, limit 10", _minimal(full_log="é" * 7), 10),
        ("inline: full_log 100 bytes, limit 5", _minimal(full_log="x" * 100), 5),
        ("inline: id missing", {"rule": {"id": "1", "description": "x"}}, default),
        (
            "inline: garbage timestamp",
            {"id": "1", "rule": {"id": "1", "description": "x"}, "timestamp": "garbage"},
            default,
        ),
        (
            "inline: rule.id missing, valid timestamp",
            {"id": "1", "rule": {"description": "x"}, "timestamp": "2026-09-02T16:15:36.255+0700"},
            default,
        ),
        ("inline: empty object", {}, default),
        ("inline: empty _source", {"_source": {}}, default),
        ("inline: id None", {"id": None}, default),
        ("inline: rule None", {"rule": None}, default),
    ]
    return cases


def _jsonable(value: object) -> object:
    """The snapshot's encoding: datetimes as ISO strings, tuples as lists, mappings as dicts."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def parse_result_json(result: ParseResult) -> dict:
    """One `ParseResult` in the snapshot's encoding: every `Alert` field, by name."""
    alert = None
    if result.alert is not None:
        alert = {
            field.name: _jsonable(getattr(result.alert, field.name))
            for field in dataclasses.fields(Alert)
        }
    return {"envelope": result.envelope, "rejection": result.rejection, "alert": alert}


_CORPUS = {name: (doc, limit) for name, doc, limit in linux_corpus()}


@functools.cache
def _snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def test_linux_corpus_and_snapshot_name_the_same_cases():
    """Same cases, same order: a document dropped from either side fails here, not silently."""
    assert len(_CORPUS) == len(linux_corpus()), "two corpus cases share a name"
    assert list(_CORPUS) == list(_snapshot()["cases"])


def test_snapshot_is_the_base_parser_at_mapping_version_v3_2():
    """Written at ba7b070, whose category tables were v3.2. `mapping_version` is the one
    field P9-T02 moves on purpose (§4 item 1 bumps it), so it is compared to the live
    constant below, never to this."""
    snapshot = _snapshot()
    assert snapshot["base_commit"] == "ba7b070"
    versions = {c["alert"]["mapping_version"] for c in snapshot["cases"].values() if c["alert"]}
    assert versions == {"v3.2"}


@pytest.mark.parametrize("name", list(_CORPUS))
def test_linux_document_parses_exactly_as_the_base_parser_did(name, monkeypatch):
    doc, limit = _CORPUS[name]
    monkeypatch.setenv("RAW_LOG_MAX_BYTES", str(limit))
    # v3.5 (DEC-216): the snapshot is the base parser's; tier 6 is switched off for the exact
    # comparison and checked on its own below — it may only fill a category the base left unknown.
    with_tier_6 = parse_result_json(parse_wazuh_alert(copy.deepcopy(doc)))
    monkeypatch.setattr(category, "EXTENDED_TECHNIQUE_TO_CATEGORY", {})
    got = parse_result_json(parse_wazuh_alert(copy.deepcopy(doc)))
    want = _snapshot()["cases"][name]
    if want["alert"] is not None and want["alert"]["category"] != "unknown":
        assert with_tier_6["alert"]["category"] == want["alert"]["category"]
        assert with_tier_6["alert"]["resolved_by"] == want["alert"]["resolved_by"]

    assert (got["envelope"], got["rejection"]) == (want["envelope"], want["rejection"])
    if want["alert"] is None:
        assert got["alert"] is None
        return
    assert list(got["alert"]) == list(want["alert"]), "the Alert field set changed"
    diff = {
        field: (got["alert"][field], expected)
        for field, expected in want["alert"].items()
        if field != "mapping_version" and got["alert"][field] != expected
    }
    assert diff == {}
    # The version label of the category tables, not a parsed value: category,
    # categories and resolved_by are compared to the base above.
    assert got["alert"]["mapping_version"] == category.MAPPING_VERSION


# ---------------------------------------------------------------------------
# 2 · one case per Windows event type — synthetic fixtures
# ---------------------------------------------------------------------------
#
# Every Windows document here is synthetic, modelled on Wazuh's documented
# `windows_eventchannel` shape. Each file under `fixtures/windows/` carries
# `"_fixture": "synthetic"` — at the top and inside `_source`, so the mark survives
# into `raw_payload` — lives only under `backend/tests/`, and is never loaded into a
# database or read by `eval/` (card §1 item 4). One real alert per event type comes
# from the Owner's Windows agent before merge.

WINDOWS_FIXTURES = FIXTURES / "windows"

#: fixture stem -> the `system.eventID` it models: the card's eight event types.
EVENT_FIXTURES: dict[str, str] = {
    "4625_network_logon_failure": "4625",
    "4624_rdp_logon_type_10": "4624",
    "4740_account_lockout": "4740",
    "sysmon_1_process_create": "1",
    "sysmon_3_network_connection": "3",
    "sysmon_11_file_create": "11",
    "sysmon_22_dns_query": "22",
    "defender_1116_detection": "1116",
}


def _win(stem: str) -> dict:
    return json.loads((WINDOWS_FIXTURES / f"synthetic_{stem}.json").read_text(encoding="utf-8"))


def _eventdata(doc: dict) -> dict:
    return doc["_source"]["data"]["win"]["eventdata"]


def _message(doc: dict) -> str:
    return doc["_source"]["data"]["win"]["system"]["message"]


def _parse(doc: dict) -> Alert:
    result = parse_wazuh_alert(doc)
    assert result.rejection is None
    return result.alert


def test_every_windows_fixture_is_synthetic_and_marked():
    stems = sorted(p.stem for p in WINDOWS_FIXTURES.glob("*.json"))
    assert set(stems) >= {f"synthetic_{stem}" for stem in EVENT_FIXTURES}
    for stem in stems:
        doc = json.loads((WINDOWS_FIXTURES / f"{stem}.json").read_text(encoding="utf-8"))
        assert stem.startswith("synthetic_"), stem
        assert doc["_fixture"] == "synthetic", stem
        assert doc["_source"]["_fixture"] == "synthetic", stem
        assert doc["_source"]["decoder"] == {"name": "windows_eventchannel"}, stem
    for stem, event_id in EVENT_FIXTURES.items():
        assert _win(stem)["_source"]["data"]["win"]["system"]["eventID"] == event_id, stem


def test_4625_network_logon_failure():
    doc = _win("4625_network_logon_failure")
    alert = _parse(doc)
    assert (alert.srcip, alert.src_port) == ("192.168.56.101", 51234)  # ipAddress, ipPort
    assert (alert.dstip, alert.dst_port) == ("", 0)
    assert alert.alert_user == "labadmin"  # targetUserName; subjectUserName is "-"
    assert alert.srcip_is_private is True
    assert (alert.raw_log, alert.raw_log_truncated) == (_message(doc), False)
    # status/subStatus/logonType are not Alert fields: they reach ① through raw_log
    # and stay in raw_payload (card §3).
    assert "0xC000006A" in alert.raw_log
    assert alert.raw_payload["data"]["win"]["eventdata"]["subStatus"] == "0xc000006a"
    # The dedup key now carries the Windows source address.
    assert alert.event_bucket_hash == compute_event_bucket_hash(
        "60122", "192.168.56.101", "", "WIN-LAB-01", alert.alert_time
    )


def test_4624_logon_type_10():
    doc = _win("4624_rdp_logon_type_10")
    alert = _parse(doc)
    assert (alert.srcip, alert.src_port) == ("10.10.20.15", 0)  # ipPort "0"
    assert alert.alert_user == "labuser"  # the new logon, not the machine account subject
    assert alert.raw_log == _message(doc)


def test_4740_account_lockout():
    doc = _win("4740_account_lockout")
    alert = _parse(doc)
    assert (alert.srcip, alert.dstip, alert.src_port, alert.dst_port) == ("", "", 0, 0)
    assert alert.alert_user == "labuser"
    assert alert.srcip_is_private is None
    assert alert.raw_log == _message(doc)


def test_sysmon_1_process_create():
    doc = _win("sysmon_1_process_create")
    alert = _parse(doc)
    assert alert.alert_user == "labuser"  # `WIN-LAB-01\labuser` -> the account part
    assert (alert.srcip, alert.dstip) == ("", "")
    assert alert.raw_log == _message(doc)


def test_sysmon_3_network_connection():
    doc = _win("sysmon_3_network_connection")
    alert = _parse(doc)
    assert (alert.srcip, alert.src_port) == ("192.168.56.20", 49811)  # sourceIp, sourcePort
    assert (alert.dstip, alert.dst_port) == ("203.0.113.80", 8443)
    assert alert.alert_user == "labuser"
    assert alert.raw_log == _message(doc)


def test_sysmon_11_file_create_without_message_falls_back_to_sorted_json():
    doc = _win("sysmon_11_file_create")
    win = doc["_source"]["data"]["win"]
    assert "message" not in win["system"]
    alert = _parse(doc)
    assert alert.raw_log == json.dumps(win, sort_keys=True, ensure_ascii=False)
    assert alert.alert_user == "labuser"


def test_sysmon_22_dns_query():
    doc = _win("sysmon_22_dns_query")
    alert = _parse(doc)
    assert alert.alert_user == "labuser"
    assert (alert.srcip, alert.dstip, alert.dst_port) == ("", "", 0)
    assert alert.raw_log == _message(doc)


def test_defender_1116_detection():
    """The card's user sources are targetUserName/subjectUserName/Sysmon `user`;
    Defender names the user under `detection User`, which is not one of them."""
    doc = _win("defender_1116_detection")
    alert = _parse(doc)
    assert alert.alert_user is None
    assert (alert.srcip, alert.dstip) == ("", "")
    assert alert.raw_log == _message(doc)


@pytest.mark.parametrize("empty", ["-", "", "  ", "127.0.0.1", "::1", "0.0.0.0"])
def test_empty_windows_address_is_no_address(empty):
    doc = _win("4625_network_logon_failure")
    _eventdata(doc)["ipAddress"] = empty
    alert = _parse(doc)
    assert alert.srcip == ""
    assert alert.srcip_is_private is None


def test_empty_ip_address_falls_back_to_source_ip():
    doc = _win("4625_network_logon_failure")
    _eventdata(doc).update(ipAddress="::1", sourceIp="192.168.56.30")
    assert _parse(doc).srcip == "192.168.56.30"


def test_empty_ip_port_falls_back_to_source_port():
    doc = _win("4625_network_logon_failure")
    _eventdata(doc).update(ipPort="-", sourcePort="49999")
    assert _parse(doc).src_port == 49999


@pytest.mark.parametrize(
    "eventdata,expected",
    [
        ({"targetUserName": "WIN-LAB-01$", "subjectUserName": "labuser"}, "labuser"),
        (
            {"targetUserName": "-", "subjectUserName": "WIN-LAB-01$", "user": "WIN-LAB-01\\lab2"},
            "lab2",
        ),
        ({"targetUserName": "", "user": "WORKGROUP\\WIN-LAB-01$"}, None),
        ({"user": "labuser"}, "labuser"),
        ({"targetUserName": " labuser "}, "labuser"),
        ({"subjectUserName": "-"}, None),
        ({}, None),
    ],
)
def test_user_order_and_empty_filters(eventdata, expected):
    doc = _win("4740_account_lockout")
    doc["_source"]["data"]["win"]["eventdata"] = eventdata
    assert _parse(doc).alert_user == expected


@pytest.mark.parametrize("message", ["", "   ", None, {"not": "a string"}])
def test_empty_or_non_string_message_falls_back_to_sorted_json(message):
    doc = _win("4740_account_lockout")
    win = doc["_source"]["data"]["win"]
    win["system"]["message"] = message
    assert _parse(doc).raw_log == json.dumps(win, sort_keys=True, ensure_ascii=False)


def test_windows_raw_log_goes_through_the_same_truncation(monkeypatch):
    monkeypatch.setenv("RAW_LOG_MAX_BYTES", "40")
    doc = _win("4625_network_logon_failure")
    alert = _parse(doc)
    assert alert.raw_log_truncated is True
    assert alert.raw_log == _message(doc).encode("utf-8")[:40].decode("utf-8")
    assert alert.raw_payload["data"]["win"]["system"]["message"] == _message(doc)  # untouched


@pytest.mark.parametrize("win", ["a string", ["a", "list"], None, 7, True])
def test_data_win_that_is_not_a_mapping_is_ignored(win):
    alert = _parse(_minimal(data={"win": win}))
    assert (alert.srcip, alert.dstip, alert.src_port, alert.dst_port) == ("", "", 0, 0)
    assert alert.alert_user is None
    assert alert.raw_log == ""


@pytest.mark.parametrize(
    "eventdata",
    [
        None,
        "x",
        [1, 2],
        {
            "ipAddress": 7,
            "ipPort": ["1"],
            "targetUserName": {"a": 1},
            "user": None,
            "destinationIp": False,
            "destinationPort": 3.5,
        },
    ],
)
def test_garbage_windows_values_never_raise(eventdata):
    doc = _win("sysmon_3_network_connection")
    doc["_source"]["data"]["win"]["eventdata"] = eventdata
    alert = _parse(doc)
    assert (alert.srcip, alert.dstip, alert.src_port, alert.dst_port) == ("", "", 0, 0)
    assert alert.alert_user is None


def test_raw_log_json_fallback_never_raises_on_a_mapping_json_cannot_produce():
    """R2: `sort_keys` cannot order an int key beside a str key; that mapping keeps an
    empty raw_log instead of raising."""
    assert _parse(_minimal(data={"win": {1: "int key", "system": {}}})).raw_log == ""


def test_windows_parse_is_deterministic_and_never_mutates_its_input():
    for stem in EVENT_FIXTURES:
        doc = _win(stem)
        before = copy.deepcopy(doc)
        first = parse_wazuh_alert(doc)
        assert first.alert == parse_wazuh_alert(doc).alert, stem
        assert doc == before, stem
        assert first.alert.raw_payload == before["_source"], stem


# ---------------------------------------------------------------------------
# 3 · no double reading — a Linux value is never replaced by a Windows one
# ---------------------------------------------------------------------------


def test_data_srcip_wins_over_win_eventdata_ip_address():
    """Card §3 test 3: a document with both `data.srcip` and
    `data.win.eventdata.ipAddress` keeps `data.srcip`."""
    doc = _win("4625_network_logon_failure")
    doc["_source"]["data"]["srcip"] = "10.9.8.7"
    assert _parse(doc).srcip == "10.9.8.7"


def test_no_linux_field_is_ever_replaced_by_a_windows_one():
    doc = _win("sysmon_3_network_connection")
    doc["_source"]["data"].update(
        srcip="10.9.8.7", dstip="10.9.8.8", srcport="1111", dstport="2222", dstuser="root"
    )
    doc["_source"]["full_log"] = "a Linux-shaped full_log line"
    alert = _parse(doc)
    assert (alert.srcip, alert.dstip) == ("10.9.8.7", "10.9.8.8")
    assert (alert.src_port, alert.dst_port) == (1111, 2222)
    assert alert.alert_user == "root"
    assert alert.raw_log == "a Linux-shaped full_log line"


def test_only_the_empty_linux_fields_are_filled():
    """`data.srcuser` set, everything else only under `data.win`: the user stays
    Linux's, the addresses and ports come from Windows."""
    doc = _win("sysmon_3_network_connection")
    doc["_source"]["data"]["srcuser"] = "eve"
    alert = _parse(doc)
    assert alert.alert_user == "eve"
    assert (alert.srcip, alert.dstip) == ("192.168.56.20", "203.0.113.80")
