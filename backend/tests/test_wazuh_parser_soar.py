"""`ingest/wazuh_parser.py` falls back to `enrichment.asset.user` for the account (P12-T02, DEC-208 item 5).

SOAR picks the right account field per scenario and posts it as `enrichment.asset.user`, with the
Windows domain in front (`FPT\\hr01`). When the parser finds no account of its own, that one is the
alert's `alert_user`, the domain part dropped. It is a fallback and nothing more:

- only when `enrichment` is a block and `asset.user` is a non-empty string; anything else leaves
  `alert_user` as it was;
- never over an account the parser did read (`data.dstuser`, `data.srcuser`, the Windows
  `eventdata` names);
- no document without an `enrichment` block changes, which `test_wazuh_parser_windows.py`'s
  snapshot of the Linux corpus pins as before.
"""

from __future__ import annotations

import copy

import pytest
from app.ingest.wazuh_parser import parse_wazuh_alert

from tests.soar_payloads import mw03 as _mw03
from tests.soar_payloads import sc03 as _sc03


def _user(doc: dict) -> str | None:
    result = parse_wazuh_alert(copy.deepcopy(doc))
    assert result.alert is not None, result.rejection
    return result.alert.alert_user


def test_the_mw03_sample_names_no_account_of_its_own() -> None:
    """The control: without the block, the Defender event gives the parser no user (its
    `detectionUser` is not a field it reads), so the fallback is what supplies `hr01` below."""
    doc = _mw03()
    del doc["enrichment"]

    assert _user(doc) is None


def test_the_mw03_sample_gives_the_account_without_its_domain() -> None:
    assert _mw03()["enrichment"]["asset"]["user"] == "FPT\\hr01"

    assert _user(_mw03()) == "hr01"


@pytest.mark.parametrize(
    "written, expected",
    [
        ("FPT\\hr01", "hr01"),
        ("hr01", "hr01"),
        ("fpt.com\\hr01", "hr01"),
        ("FPT\\corp\\hr01", "hr01"),
        ("  FPT\\hr01  ", "hr01"),
        ("  hr01 ", "hr01"),
        ("FPT\\", None),
        ("\\", None),
        ("", None),
        ("   ", None),
    ],
)
def test_the_domain_part_is_dropped_and_an_empty_account_is_none(
    written: str, expected: str | None
) -> None:
    doc = _mw03()
    doc["enrichment"]["asset"]["user"] = written

    assert _user(doc) == expected


@pytest.mark.parametrize("written", [None, 5, True, ["FPT\\hr01"], {"name": "hr01"}])
def test_a_user_that_is_not_a_string_is_not_used(written: object) -> None:
    doc = _mw03()
    doc["enrichment"]["asset"]["user"] = written

    assert _user(doc) is None


def test_a_missing_user_key_is_not_an_account() -> None:
    doc = _mw03()
    del doc["enrichment"]["asset"]["user"]

    assert _user(doc) is None


def test_the_sc03_sample_names_no_account_and_the_parser_makes_none_up() -> None:
    assert _sc03()["enrichment"]["asset"]["user"] is None

    assert _user(_sc03()) is None


@pytest.mark.parametrize(
    "enrichment",
    [
        None,
        "FPT\\hr01",
        ["FPT\\hr01"],
        5,
        {},
        {"asset": None},
        {"asset": "FPT\\hr01"},
        {"asset": []},
    ],
)
def test_without_an_enrichment_block_that_holds_an_asset_block_nothing_is_used(
    enrichment: object,
) -> None:
    doc = _mw03()
    doc["enrichment"] = enrichment

    assert _user(doc) is None


def test_a_document_without_the_enrichment_key_is_untouched() -> None:
    doc = _mw03()
    del doc["enrichment"]
    doc["asset"] = {"user": "FPT\\hr01"}  # a look-alike outside the block is not read

    assert _user(doc) is None


def test_an_invalid_schema_version_does_not_stop_the_parser_from_reading_the_user() -> None:
    """The parser is pure and knows nothing of the schema: whether to trust the block is the
    pipeline's decision (`_build_context`), and the name of an account is not a verdict."""
    doc = _mw03()
    doc["enrichment"]["schema_version"] = "2.0"

    assert _user(doc) == "hr01"


@pytest.mark.parametrize(
    "put",
    [
        lambda doc: doc.setdefault("data", {}).__setitem__("dstuser", "root"),
        lambda doc: doc.setdefault("data", {}).__setitem__("srcuser", "root"),
        lambda doc: doc["data"]["win"]["eventdata"].__setitem__("targetUserName", "root"),
        lambda doc: doc["data"]["win"]["eventdata"].__setitem__("subjectUserName", "root"),
        lambda doc: doc["data"]["win"]["eventdata"].__setitem__("user", "NT\\root"),
    ],
    ids=["dstuser", "srcuser", "targetUserName", "subjectUserName", "sysmon user"],
)
def test_an_account_the_parser_read_is_never_replaced(put) -> None:
    doc = _mw03()
    put(doc)

    assert _user(doc) == "root"


def test_the_account_is_read_inside_an_indexer_hit_too() -> None:
    hit = {"_index": "wazuh-alerts-4.x-2026.10.16", "_id": "x", "_source": _mw03()}

    assert _user(hit) == "hr01"


def test_nothing_but_the_user_changes_between_a_block_and_no_block() -> None:
    """The fallback touches `alert_user` and no other field of the `Alert`."""
    with_block = parse_wazuh_alert(_mw03()).alert
    bare = _mw03()
    del bare["enrichment"]
    without_block = parse_wazuh_alert(bare).alert
    assert with_block is not None and without_block is not None

    changed = {
        name
        for name in with_block.__dataclass_fields__
        if getattr(with_block, name) != getattr(without_block, name)
    }

    assert changed == {"alert_user", "raw_payload"}  # `raw_payload` is the document, block and all
