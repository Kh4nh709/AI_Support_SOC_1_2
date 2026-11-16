"""The nine settings of the SOAR review tickets on the web (spec 2026-11-16 §6): `infra/config.py`.

    SOAR_NOTICE_API_KEY  SOAR_NOTICE_IP_ALLOWLIST        what n8n posts to `/webhook/soar-notices` with
    N8N_APPROVAL_URL  N8N_APPROVAL_SECRET  N8N_APPROVAL_TIMEOUT_SECONDS   where the web calls n8n back
    SOAR_ROLES_KEEP  SOAR_ROLES_UNDO  SOAR_ROLES_FP      who may press which button
    SOAR_AD_HOSTS                                        the hosts whose isolation gets the strong warning

Pure: no clock, no database, no network. `.env.example` and the runbook table are pinned here as well, next to
the keys they must carry.
"""

from __future__ import annotations

import dataclasses
import pathlib
import re

import pytest
from app.infra.config import Config, load
from app.infra.errors import ConfigError

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

KEYS = (
    "SOAR_NOTICE_API_KEY",
    "SOAR_NOTICE_IP_ALLOWLIST",
    "N8N_APPROVAL_URL",
    "N8N_APPROVAL_SECRET",
    "N8N_APPROVAL_TIMEOUT_SECONDS",
    "SOAR_ROLES_KEEP",
    "SOAR_ROLES_UNDO",
    "SOAR_ROLES_FP",
    "SOAR_AD_HOSTS",
)


@pytest.fixture(autouse=True)
def _no_soar_env(monkeypatch):
    """A real environment variable beats everything: none of the nine may leak in from the host."""
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)


def _load(monkeypatch, **env: str) -> Config:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return load(env_file="/dev/null")


# ── defaults ────────────────────────────────────────────────────────────────────────────────


def test_the_defaults_are_the_specs(monkeypatch):
    cfg = _load(monkeypatch)
    assert cfg.SOAR_NOTICE_API_KEY == ""
    assert cfg.SOAR_NOTICE_IP_ALLOWLIST == []
    assert cfg.N8N_APPROVAL_URL == "http://79.79.79.14:5678/webhook/soar-approval"
    assert cfg.N8N_APPROVAL_SECRET == ""
    assert cfg.N8N_APPROVAL_TIMEOUT_SECONDS == 45
    assert cfg.SOAR_ROLES_KEEP == ["tier1", "tier2", "admin"]
    assert cfg.SOAR_ROLES_UNDO == ["tier2", "admin"]
    assert cfg.SOAR_ROLES_FP == ["tier1", "tier2", "admin"]
    assert cfg.SOAR_AD_HOSTS == ["AD-server"]


def test_a_config_built_by_hand_has_the_same_defaults_as_a_loaded_one(monkeypatch):
    """The tests build `Config()` directly and `replace` a field; that must be the configuration a bare
    `.env` gives."""
    loaded = _load(monkeypatch)
    for key in KEYS:
        assert getattr(Config(), key) == getattr(loaded, key), key


def test_the_two_secrets_default_empty_so_both_routes_start_closed(monkeypatch):
    """An empty key makes `/webhook/soar-notices` answer 503 and an empty secret makes the decision route
    answer 503: merging the feature opens nothing until the Owner sets them."""
    cfg = _load(monkeypatch)
    assert not cfg.SOAR_NOTICE_API_KEY and not cfg.N8N_APPROVAL_SECRET


def test_every_one_of_the_nine_is_a_config_field_and_a_pack_key():
    import sys

    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import gen_env_example

    fields = {f.name for f in dataclasses.fields(Config)}
    pack = set(gen_env_example.keys_from_pack())
    assert set(KEYS) <= fields
    assert set(KEYS) <= pack


# ── a value from the environment ────────────────────────────────────────────────────────────


def test_the_values_are_read_from_the_environment(monkeypatch):
    cfg = _load(
        monkeypatch,
        SOAR_NOTICE_API_KEY="k-notice",
        SOAR_NOTICE_IP_ALLOWLIST='["10.0.0.0/8", "79.79.79.14", "fd00::/8"]',
        N8N_APPROVAL_URL="https://n8n.example.test/webhook/x",
        N8N_APPROVAL_SECRET="s-approval",
        N8N_APPROVAL_TIMEOUT_SECONDS="30",
        SOAR_ROLES_KEEP="tier2,admin",
        SOAR_ROLES_UNDO="admin",
        SOAR_ROLES_FP="tier1",
        SOAR_AD_HOSTS='["DC01", "dc02.lab"]',
    )
    assert cfg.SOAR_NOTICE_API_KEY == "k-notice"
    assert cfg.SOAR_NOTICE_IP_ALLOWLIST == ["10.0.0.0/8", "79.79.79.14", "fd00::/8"]
    assert cfg.N8N_APPROVAL_URL == "https://n8n.example.test/webhook/x"
    assert cfg.N8N_APPROVAL_SECRET == "s-approval"
    assert cfg.N8N_APPROVAL_TIMEOUT_SECONDS == 30
    assert cfg.SOAR_ROLES_KEEP == ["tier2", "admin"]
    assert cfg.SOAR_ROLES_UNDO == ["admin"]
    assert cfg.SOAR_ROLES_FP == ["tier1"]
    assert cfg.SOAR_AD_HOSTS == ["DC01", "dc02.lab"]


def test_the_values_are_read_from_the_env_file_too(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SOAR_ROLES_UNDO=tier1, tier2\nN8N_APPROVAL_TIMEOUT_SECONDS=12\n", "utf-8")
    cfg = load(env_file=env)
    assert cfg.SOAR_ROLES_UNDO == ["tier1", "tier2"]
    assert cfg.N8N_APPROVAL_TIMEOUT_SECONDS == 12


# ── the role lists ──────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("key", ["SOAR_ROLES_KEEP", "SOAR_ROLES_UNDO", "SOAR_ROLES_FP"])
@pytest.mark.parametrize(
    "value",
    [
        "tier3",
        "analyst",
        "Admin",
        "tier1,boss",
        "tier1;tier2",
        "tier1,,admin",
        "tier1,",
        "*",
        "all",
    ],
)
def test_an_unknown_role_stops_the_start_up_naming_the_key(monkeypatch, key, value):
    with pytest.raises(ConfigError, match=key):
        _load(monkeypatch, **{key: value})


@pytest.mark.parametrize("key", ["SOAR_ROLES_KEEP", "SOAR_ROLES_UNDO", "SOAR_ROLES_FP"])
def test_a_role_list_is_comma_separated_spaces_allowed_and_a_repeat_counted_once(monkeypatch, key):
    cfg = _load(monkeypatch, **{key: " admin , tier2,admin "})
    assert getattr(cfg, key) == ["admin", "tier2"]


def test_the_unknown_role_is_in_the_message_but_no_other_setting_is(monkeypatch):
    monkeypatch.setenv("SOAR_NOTICE_API_KEY", "k-must-not-print")
    with pytest.raises(ConfigError) as caught:
        _load(monkeypatch, SOAR_ROLES_UNDO="tier9")
    assert "tier9" in str(caught.value)
    assert "k-must-not-print" not in str(caught.value)


# ── the timeout ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["1", "45", "99", "100"])
def test_a_timeout_from_one_to_the_ceiling_is_accepted(monkeypatch, value):
    assert _load(
        monkeypatch, N8N_APPROVAL_TIMEOUT_SECONDS=value
    ).N8N_APPROVAL_TIMEOUT_SECONDS == int(value)


@pytest.mark.parametrize("value", ["101", "120", "1000", "0", "-1", "abc", "4.5", "45s"])
def test_a_timeout_over_100_or_not_a_positive_integer_stops_the_start_up(monkeypatch, value):
    """100 is the ceiling because a lock older than two minutes is released: a live call must never look like
    a stale lock."""
    with pytest.raises(ConfigError, match="N8N_APPROVAL_TIMEOUT_SECONDS"):
        _load(monkeypatch, N8N_APPROVAL_TIMEOUT_SECONDS=value)


# ── the two JSON lists ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("key", ["SOAR_NOTICE_IP_ALLOWLIST", "SOAR_AD_HOSTS"])
@pytest.mark.parametrize("value", ["not json", "{}", '["a", 1]', '"a"', "[1, 2]", "[true]"])
def test_a_bad_json_list_stops_the_start_up_naming_the_key(monkeypatch, key, value):
    with pytest.raises(ConfigError, match=key):
        _load(monkeypatch, **{key: value})


@pytest.mark.parametrize(
    "entry", ["10.0.0.0/33", "not-an-ip", "10.0.0.256", "fd00::/129", "10.0.0.0/"]
)
def test_an_allowlist_entry_that_is_no_ip_or_cidr_stops_the_start_up(monkeypatch, entry):
    """Unlike the alerts webhook's list, whose bad entry is skipped (and so silently denies), a typo here is
    named at the start."""
    with pytest.raises(ConfigError, match="SOAR_NOTICE_IP_ALLOWLIST"):
        _load(monkeypatch, SOAR_NOTICE_IP_ALLOWLIST=f'["{entry}"]')


def test_the_ad_hosts_are_kept_as_written(monkeypatch):
    """The comparison with a review's `host` is case-insensitive and made where it is used."""
    assert _load(monkeypatch, SOAR_AD_HOSTS='["AD-server", "Dc01"]').SOAR_AD_HOSTS == [
        "AD-server",
        "Dc01",
    ]


# ── the approval URL ────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value", ["ftp://n8n/x", "n8n:5678/webhook", "file:///etc/passwd", "//n8n/x"]
)
def test_an_approval_url_that_is_not_http_or_https_stops_the_start_up(monkeypatch, value):
    with pytest.raises(ConfigError, match="N8N_APPROVAL_URL"):
        _load(monkeypatch, N8N_APPROVAL_URL=value)


@pytest.mark.parametrize(
    "value", ["http://79.79.79.14:5678/webhook/soar-approval", "https://n8n.lab/webhook/a?x=1"]
)
def test_an_http_or_https_approval_url_is_accepted(monkeypatch, value):
    assert _load(monkeypatch, N8N_APPROVAL_URL=value).N8N_APPROVAL_URL == value


# ── secrets never print ─────────────────────────────────────────────────────────────────────


def test_the_two_secrets_are_redacted_by_repr_and_dump(monkeypatch):
    cfg = _load(
        monkeypatch,
        SOAR_NOTICE_API_KEY="notice-SECRET-AAA",
        N8N_APPROVAL_SECRET="approval-SECRET-BBB",
    )
    text = repr(cfg) + repr(cfg.dump()) + str(cfg.dump())
    assert "SECRET-AAA" not in text
    assert "SECRET-BBB" not in text
    assert cfg.dump()["SOAR_NOTICE_API_KEY"] == "***"
    assert cfg.dump()["N8N_APPROVAL_SECRET"] == "***"
    # the fields themselves still hold the real value: the routes compare against them
    assert cfg.SOAR_NOTICE_API_KEY == "notice-SECRET-AAA"
    assert cfg.N8N_APPROVAL_SECRET == "approval-SECRET-BBB"


def test_an_empty_secret_is_not_masked_into_a_false_positive(monkeypatch):
    dumped = _load(monkeypatch).dump()
    assert dumped["SOAR_NOTICE_API_KEY"] == ""
    assert dumped["N8N_APPROVAL_SECRET"] == ""


def test_the_other_seven_are_shown_as_they_are(monkeypatch):
    dumped = _load(monkeypatch, N8N_APPROVAL_TIMEOUT_SECONDS="30").dump()
    assert dumped["N8N_APPROVAL_URL"] == "http://79.79.79.14:5678/webhook/soar-approval"
    assert dumped["N8N_APPROVAL_TIMEOUT_SECONDS"] == 30
    assert dumped["SOAR_ROLES_UNDO"] == ["tier2", "admin"]
    assert dumped["SOAR_AD_HOSTS"] == ["AD-server"]


# ── .env.example and the runbook carry the nine ─────────────────────────────────────────────


def _example_lines() -> dict[str, str]:
    lines = {}
    for line in (REPO_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Z][A-Z0-9_]{2,})=(.*)$", line)
        if match:
            lines[match.group(1)] = match.group(2)
    return lines


@pytest.mark.parametrize("key", KEYS)
def test_env_example_has_the_key_with_a_comment_saying_what_it_is(key):
    line = _example_lines()[key]
    assert "#" in line, f"{key} in .env.example carries no comment"


def test_env_example_carries_no_real_secret_for_the_two_secrets():
    lines = _example_lines()
    for key in ("SOAR_NOTICE_API_KEY", "N8N_APPROVAL_SECRET"):
        assert lines[key].split("#")[0].strip() == "", f"{key} must be empty in .env.example"


def test_env_example_values_are_the_defaults():
    lines = {k: v.split("#")[0].strip() for k, v in _example_lines().items()}
    assert lines["N8N_APPROVAL_URL"] == "http://79.79.79.14:5678/webhook/soar-approval"
    assert lines["N8N_APPROVAL_TIMEOUT_SECONDS"] == "45"
    assert lines["SOAR_ROLES_KEEP"] == "tier1,tier2,admin"
    assert lines["SOAR_ROLES_UNDO"] == "tier2,admin"
    assert lines["SOAR_ROLES_FP"] == "tier1,tier2,admin"
    assert lines["SOAR_AD_HOSTS"] == '["AD-server"]'
    assert lines["SOAR_NOTICE_IP_ALLOWLIST"] == ""


def test_the_example_values_load_to_the_defaults(tmp_path):
    """The template, copied to `.env` as it is, must load and give the defaults."""
    template = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    env = tmp_path / ".env"
    env.write_text(template, "utf-8")
    cfg = load(env_file=env)
    for key in KEYS:
        assert getattr(cfg, key) == getattr(Config(), key), key


def test_the_runbook_table_has_a_row_for_each_of_the_nine_and_says_who_sets_the_two_secrets():
    text = (REPO_ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    rows = {m.group(1): m.group(0) for m in re.finditer(r"(?m)^\| `([A-Z0-9_]+)` \|.*$", text)}
    for key in KEYS:
        assert key in rows, f"docs/runbook.md has no row for {key}"
    for key in ("SOAR_NOTICE_API_KEY", "N8N_APPROVAL_SECRET"):
        cells = [c.strip() for c in rows[key].strip("|").split("|")]
        assert cells[-1] == "yes", f"{key}: the secret column must say yes"
        assert cells[-2] == "Owner", f"{key}: the Owner sets it"
    assert (
        "`N8N_APPROVAL_TIMEOUT_SECONDS`" in text and "100" in rows["N8N_APPROVAL_TIMEOUT_SECONDS"]
    )
