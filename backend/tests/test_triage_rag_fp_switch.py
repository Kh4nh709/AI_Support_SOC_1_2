"""`TRIAGE_RAG_FP_BELOW_PCT` - the switch of the RAG low-match rule (DEC-219,
`docs/superpowers/specs/2026-11-15-rag-low-match-fp-rule-design.md` section 3). PURE: no database, no socket.

An integer from 0 to 100, default `0` (off: the rule never applies and a run is exactly what it is today).
Any other value stops the start-up naming the key, like the module's other closed-set keys. It is a context
pack §6.3 key (so a `Config` field, and a line of `.env.example`, which `scripts/gen_env_example.py --check`
keeps equal to §6.3) and a row of the runbook's environment table (`test_runbook_env_keys.py` keeps that equal
to `.env.example`).
"""

from __future__ import annotations

import dataclasses
import pathlib
import re
import sys

import pytest
from app.infra.config import Config, load
from app.infra.errors import ConfigError

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import gen_env_example

KEY = "TRIAGE_RAG_FP_BELOW_PCT"


def test_the_default_is_0_when_unset(monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    assert load(env_file="/dev/null").TRIAGE_RAG_FP_BELOW_PCT == 0


def test_the_field_default_is_0():
    field = {f.name: f for f in dataclasses.fields(Config)}[KEY]
    assert field.default == 0
    assert Config().TRIAGE_RAG_FP_BELOW_PCT == 0


@pytest.mark.parametrize(
    "raw, expected", [("0", 0), ("1", 1), ("80", 80), ("99", 99), ("100", 100)]
)
def test_an_integer_from_0_to_100_is_accepted(monkeypatch, raw, expected):
    monkeypatch.setenv(KEY, raw)
    value = load(env_file="/dev/null").TRIAGE_RAG_FP_BELOW_PCT
    assert value == expected and isinstance(value, int)


@pytest.mark.parametrize("raw", ["-1", "101", "1000", "-80"])
def test_a_number_outside_0_to_100_is_a_configuration_error_naming_the_key_and_the_range(
    monkeypatch, raw
):
    monkeypatch.setenv(KEY, raw)
    with pytest.raises(ConfigError, match=KEY) as exc_info:
        load(env_file="/dev/null")
    assert "0" in str(exc_info.value) and "100" in str(exc_info.value)


@pytest.mark.parametrize("raw", ["eighty", "80.5", "0.8", "true", "80%", "8 0"])
def test_a_value_that_is_not_an_integer_is_a_configuration_error_naming_the_key(monkeypatch, raw):
    monkeypatch.setenv(KEY, raw)
    with pytest.raises(ConfigError, match=KEY):
        load(env_file="/dev/null")


def test_the_dotenv_file_is_read_like_every_other_key(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    env = tmp_path / ".env"
    env.write_text("TRIAGE_RAG_FP_BELOW_PCT=80\n", encoding="utf-8")
    assert load(env_file=env).TRIAGE_RAG_FP_BELOW_PCT == 80


def test_it_is_a_context_pack_key():
    assert KEY in gen_env_example.keys_from_pack()


def test_env_example_lists_it_at_the_default():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    lines = [ln for ln in example.splitlines() if ln.startswith(f"{KEY}=")]
    assert len(lines) == 1
    assert re.fullmatch(rf"{KEY}=0(\s+#.*)?", lines[0]), lines[0]


def test_the_runbook_environment_table_has_a_row_for_it_that_names_the_rule_and_the_trial():
    text = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    section = text.split("\n## Environment keys")[1].split("\n## ")[0]
    rows = re.findall(rf"(?m)^\| `{KEY}` \| (.*)$", section)
    assert len(rows) == 1
    what, who, secret = (cell.strip() for cell in rows[0].rstrip("|").split(" | "))
    assert "DEC-219" in what and "`false_positive`" in what
    assert "`0`" in what and "80" in what  # off by default; the trial's value
    assert who == "Owner" and secret == "no"  # the trial's value differs from the default


def test_the_runbook_row_says_to_recreate_the_containers_and_how_to_check_it_not_to_restart_them():
    """`.env` is read when a container is created, so `restart` never sees an edit (the runbook's own rule,
    "The switches" section): the row says `up -d --force-recreate app worker rag-worker`, then how to read the
    value back from the running container, and never `restart`."""
    text = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    section = text.split("\n## Environment keys")[1].split("\n## ")[0]
    what = re.findall(rf"(?m)^\| `{KEY}` \| (.*)$", section)[0]
    flat = " ".join(what.split())
    assert "docker compose up -d --force-recreate app worker rag-worker" in flat
    assert f"docker compose exec -T app printenv {KEY}" in flat
    assert "restart" not in flat.replace("`restart` never sees", "")  # only to say why not
    assert "`restart` never sees" in flat
