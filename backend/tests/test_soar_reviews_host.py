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
        ("ǅ.LAB", "ǆ.lab"),  # case folded, not only lower-cased
        ("STRASSE", "strasse"),
        ("straße", "strasse"),
        (".", ""),
        ("..", "."),  # one trailing dot only
    ],
)
def test_the_normal_form(raw, expected):
    assert reviews.normalise_host(raw) == expected
