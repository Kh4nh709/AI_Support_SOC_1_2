"""`ingest/wazuh_parser.py` fills `event_time` from the payload (S4).

`event_time` is the instant the event happened on the endpoint; `alert_time` is when Wazuh raised the
alert, and stays as it was (required, from `fields.timestamp[0]` or `timestamp`). The parser reads
`event_time` from, in order:

1. `timing.event_time` at the root of the document (SOAR sends it beside the alert, not inside
   `_source`), ISO-8601 with an offset (`2026-10-16T03:25:22.355+0700`);
2. `data.win.system.systemTime` of the alert (a Windows event's own clock, UTC `Z`);
3. nothing: `None`.

Either value is stored in UTC. A value that is present but is not an instant (garbage, the wrong type,
no offset, out of range) is skipped for the next source and ends as `None`: it never raises and,
unlike `alert_time`, never rejects the alert.

Every document here is inline and minimal; nothing is read from the SOAR team's example files, bar one
check against the repo's copy of a real sample.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime

import pytest
from app.ingest.wazuh_parser import parse_wazuh_alert

from tests.soar_payloads import mw03 as _mw03

ABSENT = object()
TIMESTAMP = "2026-10-16T03:25:30.000+0700"  # the alert's own `timestamp`: 20:25:30 UTC
TIMING = "2026-10-16T03:25:22.355+0700"  # the same instant as 2026-10-15T20:25:22.355 UTC
TIMING_UTC = datetime(2026, 10, 15, 20, 25, 22, 355_000, tzinfo=UTC)
SYSTEM_TIME = "2026-10-15T20:25:21.5000000Z"
SYSTEM_TIME_UTC = datetime(2026, 10, 15, 20, 25, 21, 500_000, tzinfo=UTC)


def _doc(*, timing: object = ABSENT, system_time: object = ABSENT, timestamp: object = TIMESTAMP):
    """A bare alert. `timing` is the value of `timing.event_time` (the whole `timing` key when it
    is not `ABSENT`); `system_time` is `data.win.system.systemTime`."""
    doc: dict = {
        "id": "1.1",
        "rule": {"id": "100", "description": "d"},
        "timestamp": timestamp,
    }
    if timing is not ABSENT:
        doc["timing"] = {"event_time": timing}
    if system_time is not ABSENT:
        doc["data"] = {"win": {"system": {"systemTime": system_time}}}
    return doc


def _parse(doc: dict):
    result = parse_wazuh_alert(copy.deepcopy(doc))
    assert result.rejection is None, result.rejection
    assert result.alert is not None
    return result.alert


def test_timing_event_time_is_stored_in_utc() -> None:
    alert = _parse(_doc(timing=TIMING))

    assert alert.event_time == TIMING_UTC
    assert alert.event_time.isoformat() == "2026-10-15T20:25:22.355000+00:00"
    assert alert.event_time.utcoffset() == UTC.utcoffset(None)  # converted, not just equal


def test_system_time_is_used_when_there_is_no_timing() -> None:
    alert = _parse(_doc(system_time=SYSTEM_TIME))

    assert alert.event_time == SYSTEM_TIME_UTC
    assert alert.event_time.utcoffset() == UTC.utcoffset(None)


def test_system_time_with_seven_fraction_digits_is_read() -> None:
    """Windows writes `.3551523Z`; the sixth digit is the last that counts."""
    alert = _parse(_doc(system_time="2026-10-15T20:25:22.3551523Z"))

    assert alert.event_time == datetime(2026, 10, 15, 20, 25, 22, 355_152, tzinfo=UTC)


def test_timing_wins_over_system_time() -> None:
    both = _parse(_doc(timing=TIMING, system_time=SYSTEM_TIME))

    assert both.event_time == TIMING_UTC
    assert both.event_time != SYSTEM_TIME_UTC


def test_neither_source_gives_none_and_the_alert_is_not_rejected() -> None:
    alert = _parse(_doc())

    assert alert.event_time is None
    assert alert.alert_time == datetime(2026, 10, 15, 20, 25, 30, tzinfo=UTC)


GARBAGE = [
    pytest.param("not-a-time", id="text"),
    pytest.param("", id="empty"),
    pytest.param("   ", id="blank"),
    pytest.param("2026-13-45T25:61:61+0700", id="out-of-range-fields"),
    pytest.param("2026-10-16T03:25:22.355", id="no-offset"),
    pytest.param("2026-10-16", id="date-only-no-offset"),
    pytest.param(1760577922, id="number"),
    pytest.param(True, id="bool"),
    pytest.param(None, id="null"),
    pytest.param(["2026-10-16T03:25:22.355+0700"], id="list"),
    pytest.param({"at": TIMING}, id="mapping"),
    pytest.param("0001-01-01T00:00:00+07:00", id="overflows-in-utc"),
    pytest.param("9999-12-31T23:59:59-07:00", id="overflows-in-utc-after"),
]


@pytest.mark.parametrize("garbage", GARBAGE)
def test_a_timing_that_is_not_an_instant_falls_back_to_system_time(garbage: object) -> None:
    alert = _parse(_doc(timing=garbage, system_time=SYSTEM_TIME))

    assert alert.event_time == SYSTEM_TIME_UTC


@pytest.mark.parametrize("garbage", GARBAGE)
def test_a_timing_that_is_not_an_instant_and_no_system_time_gives_none(garbage: object) -> None:
    alert = _parse(_doc(timing=garbage))

    assert alert.event_time is None
    assert alert.alert_time == datetime(2026, 10, 15, 20, 25, 30, tzinfo=UTC)


@pytest.mark.parametrize("garbage", GARBAGE)
def test_a_system_time_that_is_not_an_instant_gives_none_not_a_rejection(garbage: object) -> None:
    assert _parse(_doc(system_time=garbage)).event_time is None
    assert _parse(_doc(timing=garbage, system_time=garbage)).event_time is None


@pytest.mark.parametrize("timing", ["2026-10-16T03:25:22.355+0700", None, "x", [], 5])
def test_a_timing_block_that_is_not_a_mapping_is_ignored(timing: object) -> None:
    doc = _doc(system_time=SYSTEM_TIME)
    doc["timing"] = timing

    assert _parse(doc).event_time == SYSTEM_TIME_UTC


def test_a_timing_block_without_an_event_time_falls_back_to_system_time() -> None:
    doc = _doc(system_time=SYSTEM_TIME)
    doc["timing"] = {"sent_at": "2026-10-15T20:27:54.420Z"}

    assert _parse(doc).event_time == SYSTEM_TIME_UTC


@pytest.mark.parametrize("win", [None, "x", [], {"system": None}, {"system": []}, {"system": {}}])
def test_a_win_block_that_holds_no_system_time_gives_none(win: object) -> None:
    doc = _doc()
    doc["data"] = {"win": win}

    assert _parse(doc).event_time is None


def test_a_bad_event_time_does_not_touch_alert_time_or_the_timestamp_rejection() -> None:
    """`alert_time` keeps its own rules: still required, still the only reason to reject."""
    ok = _parse(_doc(timing="garbage"))
    assert ok.alert_time == datetime(2026, 10, 15, 20, 25, 30, tzinfo=UTC)

    # a good event_time does not stand in for a missing alert_time
    for timestamp in (ABSENT, None, "garbage"):
        doc = _doc(timing=TIMING, system_time=SYSTEM_TIME, timestamp=timestamp)
        if timestamp is ABSENT:
            del doc["timestamp"]
        result = parse_wazuh_alert(copy.deepcopy(doc))
        assert result.alert is None
        assert result.rejection == "timestamp"


def test_event_time_is_not_alert_time() -> None:
    alert = _parse(_doc(timing=TIMING, system_time=SYSTEM_TIME))

    assert alert.alert_time == datetime(2026, 10, 15, 20, 25, 30, tzinfo=UTC)
    assert alert.event_time != alert.alert_time


def test_an_indexer_hit_reads_timing_at_the_document_root_and_system_time_in_the_source() -> None:
    inner = _doc(system_time=SYSTEM_TIME)
    hit = {"_id": "x", "_source": inner, "timing": {"event_time": TIMING}}
    assert _parse(hit).event_time == TIMING_UTC

    without_timing = {"_id": "x", "_source": inner}
    assert _parse(without_timing).event_time == SYSTEM_TIME_UTC


def test_the_raw_payload_is_not_changed_by_it() -> None:
    doc = _doc(timing=TIMING, system_time=SYSTEM_TIME)

    assert _parse(doc).raw_payload == doc


def test_the_real_mw03_sample_gives_its_timing_event_time() -> None:
    """The repo's copy of the SOAR team's Defender sample: `timing.event_time` is
    `2026-10-16T03:25:22.355+0700`."""
    sample = _mw03()
    assert sample["timing"]["event_time"] == "2026-10-16T03:25:22.355+0700"

    assert _parse(sample).event_time == TIMING_UTC
