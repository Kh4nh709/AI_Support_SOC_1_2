"""`LLM_RESPONSE_FORMAT` — the switch that makes ① ask the provider to enforce the output schema (DEC-218,
`docs/superpowers/specs/2026-11-15-llm-json-schema-output-design.md` section 4). PURE: no database, no socket.

`json_object` (the default) or `json_schema`; any other value stops the start-up naming the key, like the
module's other closed-set keys. It is a context pack §6.3 key (so a `Config` field, and a line of
`.env.example`, which `scripts/gen_env_example.py --check` keeps equal to §6.3) and a row of the runbook's
environment table (`test_runbook_env_keys.py` keeps that equal to `.env.example`).
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

KEY = "LLM_RESPONSE_FORMAT"


def test_the_default_is_json_object_when_unset(monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    assert load(env_file="/dev/null").LLM_RESPONSE_FORMAT == "json_object"


def test_the_field_default_is_json_object():
    field = {f.name: f for f in dataclasses.fields(Config)}[KEY]
    assert field.default == "json_object"
    assert Config().LLM_RESPONSE_FORMAT == "json_object"


def test_json_schema_is_accepted(monkeypatch):
    monkeypatch.setenv(KEY, "json_schema")
    assert load(env_file="/dev/null").LLM_RESPONSE_FORMAT == "json_schema"


def test_json_object_is_accepted(monkeypatch):
    monkeypatch.setenv(KEY, "json_object")
    assert load(env_file="/dev/null").LLM_RESPONSE_FORMAT == "json_object"


@pytest.mark.parametrize("raw", ["text", "json", "JSON_SCHEMA", "schema", "true", "1"])
def test_another_value_is_a_configuration_error_naming_the_key_and_the_choices(monkeypatch, raw):
    monkeypatch.setenv(KEY, raw)
    with pytest.raises(ConfigError, match=KEY) as exc_info:
        load(env_file="/dev/null")
    message = str(exc_info.value)
    assert "json_object" in message and "json_schema" in message


def test_the_dotenv_file_is_read_like_every_other_key(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY, raising=False)
    env = tmp_path / ".env"
    env.write_text("LLM_RESPONSE_FORMAT=json_schema\n", encoding="utf-8")
    assert load(env_file=env).LLM_RESPONSE_FORMAT == "json_schema"


def test_it_is_a_context_pack_key():
    assert KEY in gen_env_example.keys_from_pack()


def test_env_example_lists_it_at_the_default():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    lines = [ln for ln in example.splitlines() if ln.startswith(f"{KEY}=")]
    assert lines == [f"{KEY}=json_object"]


def test_the_runbook_environment_table_has_a_row_for_it_that_names_both_values_and_the_trial():
    text = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    section = text.split("\n## Environment keys")[1].split("\n## ")[0]
    rows = re.findall(rf"(?m)^\| `{KEY}` \| (.*)$", section)
    assert len(rows) == 1
    what, who, secret = (cell.strip() for cell in rows[0].rstrip("|").split(" | "))
    assert "`json_object`" in what and "`json_schema`" in what
    assert "DEC-218" in what
    assert (
        who == "Owner" and secret == "no"
    )  # the trial's value differs from the default: the Owner sets it


def test_the_runbook_row_says_to_recreate_the_containers_and_how_to_check_it_not_to_restart_them():
    """`.env` is read when a container is created, so `restart` never sees an edit (the runbook's own rule,
    "The switches" section): the row says `up -d --force-recreate app worker rag-worker`, then how to read the
    value back from the running container, and never `restart`."""
    text = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")
    section = text.split("\n## Environment keys")[1].split("\n## ")[0]
    what = re.findall(rf"(?m)^\| `{KEY}` \| (.*)$", section)[0]
    flat = " ".join(what.split())
    assert "docker compose up -d --force-recreate app worker rag-worker" in flat
    assert "docker compose exec -T app printenv LLM_RESPONSE_FORMAT" in flat
    assert "`json_schema`" in flat.split("printenv LLM_RESPONSE_FORMAT")[1]  # what it should print
    assert "restart" not in flat.replace("`restart` never sees", "")  # only to say why not
    assert "`restart` never sees" in flat
