"""SR-T1 — `soar.reviews.strong_warning` and the name it compares (spec 2026-11-16 §4, amended): a ticket gets the strong warning
when its action is an isolation, or when its `host` names a host of `SOAR_AD_HOSTS` (the lab's domain controller).

The comparison is on a NORMALISED name, so that a host written with a trailing dot, a zone, another case, or a character nobody
can see is still the domain controller: control, zero-width and bidi characters and surrounding whitespace are removed, a trailing
dot is removed, case is folded; then the whole name, or its first DNS label, must equal a name of the list (normalised the same
way). Pure: no database.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from app.infra.config import Config
from app.soar import reviews

CFG = Config()  # SOAR_AD_HOSTS = ["AD-server"]


def _warns(host: str | None, *, action_type: str | None = "block_ip", cfg: Config = CFG) -> bool:
    return reviews.strong_warning(action_type, host, cfg)


@pytest.mark.parametrize(
    "host",
    [
        "AD-server",
        "ad-server",
        "AD-SERVER",
        "ad-SERVER.",  # a trailing dot (a fully qualified name)
        "AD-server.home.arpa",  # the first label is the domain controller
        "ad-server.HOME.arpa.",
        "AD\u200b-server",  # zero-width space inside
        "A\u200cD\u200d-ser\u2060ver",  # zero-width non-joiner, joiner, word joiner
        "\ufeffAD-server",  # a byte-order mark
        "AD-server\u202e",  # a right-to-left override after it
        "\u202aAD\u202c-server",  # left-to-right embedding and its end
        "\u2066AD-server\u2069",  # isolates
        "AD\u200e-\u200fserver",  # the two direction marks
        "AD-ser\x07ver",  # a control character
        "AD-server\t",
        "  AD-server  ",
        "\xa0AD-server\xa0",  # no-break spaces
        "\n AD-server.\r\n",
        "AD-server. ",  # the dot is trailing once the space is gone
    ],
    ids=repr,
)
def test_these_are_the_domain_controller(host):
    assert _warns(host) is True


@pytest.mark.parametrize(
    "host",
    [
        None,
        "",
        ".",
        "  ",
        "\u200b",
        "notAD-server",  # not a suffix match
        "xAD-server",
        "AD-server2",  # not a prefix match
        "AD-server2.home.arpa",
        "AD-serve",
        "AD server",  # a space inside is a different name
        "AD--server",
        "home.arpa",
        "pfSense.home.arpa",
        "server.AD-server",  # only the first label counts
        "AD-ser ver",
    ],
    ids=repr,
)
def test_these_are_not(host):
    assert _warns(host) is False


def test_an_isolation_is_always_strong_whatever_the_host():
    assert _warns("PC-17", action_type="isolate_host") is True
    assert _warns(None, action_type="isolate_host") is True
    assert _warns("PC-17", action_type="disable_user") is False


def test_the_names_of_the_list_are_normalised_the_same_way():
    cfg = replace(Config(), SOAR_AD_HOSTS=["  DC01.\u200b", "Dc02.Lab.", "AD-server"])
    assert _warns("dc01", cfg=cfg) is True
    assert _warns("DC01.lab.home", cfg=cfg) is True  # first label
    assert _warns("dc02.lab", cfg=cfg) is True  # the whole name of a name with a zone
    assert _warns("DC02.LAB.", cfg=cfg) is True
    assert (
        _warns("dc02", cfg=cfg) is False
    )  # the list names the zone: the bare first label is not that name
    assert _warns("AD-server.x", cfg=cfg) is True
    assert _warns("dc03", cfg=cfg) is False


def test_an_empty_name_in_the_list_matches_no_host():
    cfg = replace(Config(), SOAR_AD_HOSTS=["", " ", "\u200b", "."])
    for host in (None, "", ".", " ", "\u200b", "anything", ".x"):
        assert _warns(host, cfg=cfg) is False


def test_an_empty_list_warns_for_isolations_only():
    cfg = replace(Config(), SOAR_AD_HOSTS=[])
    assert _warns("AD-server", cfg=cfg) is False
    assert _warns("AD-server", action_type="isolate_host", cfg=cfg) is True


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("AD-server", "ad-server"),
        ("  Ad-Server.  ", "ad-server"),
        ("AD\u200b-\u202eserver\u2069", "ad-server"),
        (
            "\u01c5.LAB",
            "d\u017e.lab",
        ),  # NFKC splits the digraph into D and z with a caron, then the case is folded
        ("STRASSE", "strasse"),
        ("straße", "strasse"),
        (".", ""),
        ("..", "."),  # one trailing dot only
    ],
)
def test_the_normal_form(raw, expected):
    assert reviews.normalise_host(raw) == expected


# ── host_critical (the UI re-review): WHY the warning is strong ────────────────────────────


@pytest.mark.parametrize(
    "action_type,host,strong,critical",
    [
        (
            "isolate_host",
            "PC-17",
            True,
            False,
        ),  # an isolation on an ordinary host: strong, not critical
        ("isolate_host", None, True, False),
        ("disable_user", "AD-server", True, True),  # an account on the domain controller: both
        ("block_ip", "ad-SERVER.", True, True),
        ("block_ip", "AD-server.home.arpa", True, True),
        ("isolate_host", "AD-server", True, True),  # an isolation of the domain controller: both
        ("block_ip", "PC-17", False, False),  # neither
        ("block_ip", None, False, False),
        ("kill_process", "notAD-server", False, False),
        ("sinkhole_domain", "AD-server2", False, False),
    ],
)
def test_host_critical_is_the_name_comparison_alone_and_strong_is_isolation_or_critical(
    action_type, host, strong, critical
):
    assert reviews.host_critical(host, CFG) is critical
    assert reviews.strong_warning(action_type, host, CFG) is strong
    assert strong == (action_type == "isolate_host" or critical)


def test_host_critical_follows_the_list_and_ignores_the_action():
    cfg = replace(Config(), SOAR_AD_HOSTS=["DC01"])
    assert reviews.host_critical("dc01.lab.", cfg) is True
    assert reviews.host_critical("AD-server", cfg) is False
    assert reviews.host_critical("dc01", replace(Config(), SOAR_AD_HOSTS=[])) is False


# ── m7: NFKC before case folding ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "host",
    [
        "ＡＤ－ｓｅｒｖｅｒ",  # fullwidth letters and hyphen
        "AD-server．",  # a fullwidth full stop as the trailing dot
        "ＡＤ-server．home．arpa",  # fullwidth dots as the label separators
        "A\u200bＤ-ｓerver",  # an invisible character and fullwidth letters
    ],
    ids=repr,
)
def test_m7_a_compatibility_form_of_the_name_is_the_domain_controller(host):
    assert reviews.strong_warning("block_ip", host, CFG) is True
    assert reviews.host_critical(host, CFG) is True


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ＡＤ－ｓｅｒｖｅｒ", "ad-server"),
        ("ﬁle", "file"),  # the ligature fi
        ("①", "1"),  # a circled digit
        (
            "AD．",
            "ad",
        ),  # NFKC maps the fullwidth full stop to a dot, which is then the trailing one
        (" AD-server ", "ad-server"),  # a no-break space is a space after NFKC
    ],
)
def test_m7_the_normal_form_applies_nfkc_before_the_case_is_folded(raw, expected):
    assert reviews.normalise_host(raw) == expected


def test_m7_a_name_that_only_looks_alike_is_still_not_the_name():
    assert (
        reviews.host_critical("AD-servеr", CFG) is False
    )  # a Cyrillic e: NFKC does not fold scripts
