"""Unit tests for app.infra.config — pure, no clock/DB/network."""

from __future__ import annotations

import dataclasses
import pathlib
import re
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
import gen_env_example
from app.infra.config import Config, load
from app.infra.errors import ConfigError


def write_env(tmp_path: pathlib.Path, text: str) -> pathlib.Path:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


class TestKeySetParity:
    def test_every_pack_key_is_a_config_field_and_vice_versa(self):
        pack = set(gen_env_example.keys_from_pack())
        fields = {f.name for f in dataclasses.fields(Config)}
        assert pack - fields == set(), f"missing from Config: {sorted(pack - fields)}"
        assert fields - pack == set(), f"not a §6.3 key: {sorted(fields - pack)}"

    def test_llm_enabled_is_a_property_not_a_field(self):
        fields = {f.name for f in dataclasses.fields(Config)}
        assert "llm_enabled" not in fields
        assert isinstance(Config.llm_enabled, property)


class TestDefaultsWithNoEnvAndNoFile:
    def test_worktree_defaults_match_task_acceptance_3(self, monkeypatch):
        monkeypatch.delenv("PULL_PAGE", raising=False)
        monkeypatch.delenv("JOB_BACKOFF", raising=False)
        monkeypatch.delenv("LLM_THINKING", raising=False)
        monkeypatch.delenv("LLM_MODEL_PROPOSER", raising=False)
        monkeypatch.delenv("INVENTORY_PATHS", raising=False)
        c = load(env_file="/dev/null")
        assert c.PULL_PAGE == 500
        assert c.JOB_BACKOFF == [10, 60, 300]
        assert c.LLM_THINKING == "disabled"
        assert c.llm_enabled is False
        assert c.INVENTORY_PATHS[0] == "conf/inventory.yaml"

    def test_no_env_file_at_all_still_loads(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PULL_PAGE", raising=False)
        missing = tmp_path / "does-not-exist" / ".env"
        c = load(env_file=missing)
        assert c.PULL_PAGE == 500

    def test_database_url_defaults_empty(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        c = load(env_file="/dev/null")
        assert c.DATABASE_URL == ""

    def test_database_url_owner_default(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL_OWNER", raising=False)
        c = load(env_file="/dev/null")
        assert c.DATABASE_URL_OWNER == "postgresql:///soc_dev"

    def test_test_database_url_default(self, monkeypatch):
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
        c = load(env_file="/dev/null")
        assert c.TEST_DATABASE_URL == "postgresql:///soc_test"

    def test_never_autoclose_agents_default_empty_list(self, monkeypatch):
        monkeypatch.delenv("NEVER_AUTOCLOSE_AGENTS", raising=False)
        c = load(env_file="/dev/null")
        assert c.NEVER_AUTOCLOSE_AGENTS == []

    def test_eval_blind_fraction_default_is_a_float(self, monkeypatch):
        monkeypatch.delenv("EVAL_BLIND_FRACTION", raising=False)
        c = load(env_file="/dev/null")
        assert c.EVAL_BLIND_FRACTION == 0.5
        assert isinstance(c.EVAL_BLIND_FRACTION, float)

    def test_display_tz_default(self, monkeypatch):
        monkeypatch.delenv("DISPLAY_TZ", raising=False)
        c = load(env_file="/dev/null")
        assert c.DISPLAY_TZ == "Asia/Ho_Chi_Minh"


class TestLlmModelVerifierDefaultsToProposer:
    def test_verifier_defaults_to_proposer_when_unset(self, monkeypatch):
        monkeypatch.setenv("LLM_MODEL_PROPOSER", "deepseek-v4-flash")
        monkeypatch.delenv("LLM_MODEL_VERIFIER", raising=False)
        c = load(env_file="/dev/null")
        assert c.LLM_MODEL_VERIFIER == "deepseek-v4-flash"

    def test_verifier_defaults_to_proposer_when_set_empty(self, monkeypatch):
        monkeypatch.setenv("LLM_MODEL_PROPOSER", "deepseek-v4-flash")
        monkeypatch.setenv("LLM_MODEL_VERIFIER", "")
        c = load(env_file="/dev/null")
        assert c.LLM_MODEL_VERIFIER == "deepseek-v4-flash"

    def test_verifier_explicit_value_is_kept(self, monkeypatch):
        monkeypatch.setenv("LLM_MODEL_PROPOSER", "deepseek-v4-flash")
        monkeypatch.setenv("LLM_MODEL_VERIFIER", "deepseek-v4-pro")
        c = load(env_file="/dev/null")
        assert c.LLM_MODEL_VERIFIER == "deepseek-v4-pro"

    def test_proposer_empty_is_not_an_error_and_disables_llm(self, monkeypatch):
        monkeypatch.delenv("LLM_MODEL_PROPOSER", raising=False)
        c = load(env_file="/dev/null")
        assert c.LLM_MODEL_PROPOSER == ""
        assert c.llm_enabled is False

    def test_proposer_set_enables_llm(self, monkeypatch):
        monkeypatch.setenv("LLM_MODEL_PROPOSER", "deepseek-v4-flash")
        c = load(env_file="/dev/null")
        assert c.llm_enabled is True


class TestJsonListParsing:
    def test_job_backoff_bad_json_raises_naming_the_key(self, monkeypatch):
        monkeypatch.setenv("JOB_BACKOFF", '[10,"x"]')
        with pytest.raises(ConfigError, match="JOB_BACKOFF"):
            load(env_file="/dev/null")

    def test_inventory_paths_not_a_list_raises_naming_the_key(self, monkeypatch):
        monkeypatch.setenv("INVENTORY_PATHS", '{"a":1}')
        with pytest.raises(ConfigError, match="INVENTORY_PATHS"):
            load(env_file="/dev/null")

    def test_inventory_paths_malformed_json_raises_naming_the_key(self, monkeypatch):
        monkeypatch.setenv("INVENTORY_PATHS", "not json at all")
        with pytest.raises(ConfigError, match="INVENTORY_PATHS"):
            load(env_file="/dev/null")

    def test_job_backoff_valid_json_parses_to_int_list(self, monkeypatch):
        monkeypatch.setenv("JOB_BACKOFF", "[1, 2, 3]")
        c = load(env_file="/dev/null")
        assert c.JOB_BACKOFF == [1, 2, 3]

    def test_job_backoff_rejects_bool_as_int(self, monkeypatch):
        monkeypatch.setenv("JOB_BACKOFF", "[true, false]")
        with pytest.raises(ConfigError, match="JOB_BACKOFF"):
            load(env_file="/dev/null")

    def test_inventory_paths_valid_json_parses_to_str_list(self, monkeypatch):
        monkeypatch.setenv("INVENTORY_PATHS", '["a.yaml", "b.yaml"]')
        c = load(env_file="/dev/null")
        assert c.INVENTORY_PATHS == ["a.yaml", "b.yaml"]

    def test_empty_value_falls_back_to_default_not_an_error(self, monkeypatch):
        monkeypatch.setenv("JOB_BACKOFF", "")
        c = load(env_file="/dev/null")
        assert c.JOB_BACKOFF == [10, 60, 300]

    def test_webhook_ip_allowlist_json_list_of_str(self, monkeypatch):
        monkeypatch.setenv("WEBHOOK_IP_ALLOWLIST", '["10.0.0.0/8"]')
        c = load(env_file="/dev/null")
        assert c.WEBHOOK_IP_ALLOWLIST == ["10.0.0.0/8"]

    def test_never_autoclose_agents_json_list_of_str(self, monkeypatch):
        monkeypatch.setenv("NEVER_AUTOCLOSE_AGENTS", '["001", "002"]')
        c = load(env_file="/dev/null")
        assert c.NEVER_AUTOCLOSE_AGENTS == ["001", "002"]


class TestClosedSet:
    def test_llm_thinking_invalid_value_names_key_and_choices(self, monkeypatch):
        monkeypatch.setenv("LLM_THINKING", "maybe")
        with pytest.raises(ConfigError, match="LLM_THINKING") as exc_info:
            load(env_file="/dev/null")
        message = str(exc_info.value)
        assert "enabled" in message and "disabled" in message

    def test_llm_thinking_enabled_is_accepted(self, monkeypatch):
        monkeypatch.setenv("LLM_THINKING", "enabled")
        c = load(env_file="/dev/null")
        assert c.LLM_THINKING == "enabled"

    def test_llm_thinking_disabled_is_accepted(self, monkeypatch):
        monkeypatch.setenv("LLM_THINKING", "disabled")
        c = load(env_file="/dev/null")
        assert c.LLM_THINKING == "disabled"

    def test_llm_thinking_default_is_disabled_per_dec_042(self, monkeypatch):
        monkeypatch.delenv("LLM_THINKING", raising=False)
        c = load(env_file="/dev/null")
        assert c.LLM_THINKING == "disabled"


class TestDedupEnabled:
    """P10-T15 / DEC-165: the one bool key. Default true (phase-2 grouping stays on
    wherever nobody says otherwise); the Owner turns it off in the live `.env`."""

    def test_default_is_true_when_unset(self, monkeypatch):
        monkeypatch.delenv("DEDUP_ENABLED", raising=False)
        c = load(env_file="/dev/null")
        assert c.DEDUP_ENABLED is True

    def test_empty_value_falls_back_to_the_default_true(self, monkeypatch):
        monkeypatch.setenv("DEDUP_ENABLED", "")
        assert load(env_file="/dev/null").DEDUP_ENABLED is True

    @pytest.mark.parametrize("raw", ["false", "False", "FALSE", "0", "no", "off", " false "])
    def test_false_spellings_turn_it_off(self, monkeypatch, raw):
        monkeypatch.setenv("DEDUP_ENABLED", raw)
        assert load(env_file="/dev/null").DEDUP_ENABLED is False

    @pytest.mark.parametrize("raw", ["true", "True", "TRUE", "1", "yes", "on"])
    def test_true_spellings_keep_it_on(self, monkeypatch, raw):
        monkeypatch.setenv("DEDUP_ENABLED", raw)
        assert load(env_file="/dev/null").DEDUP_ENABLED is True

    @pytest.mark.parametrize("raw", ["flase", "2", "enabled", "nope"])
    def test_anything_else_raises_naming_the_key_never_a_silent_default(self, monkeypatch, raw):
        monkeypatch.setenv("DEDUP_ENABLED", raw)
        with pytest.raises(ConfigError, match="DEDUP_ENABLED"):
            load(env_file="/dev/null")

    def test_dotenv_file_is_read_like_every_other_key(self, tmp_path, monkeypatch):
        monkeypatch.delenv("DEDUP_ENABLED", raising=False)
        env_path = write_env(tmp_path, "DEDUP_ENABLED=false  # DEC-165, live\n")
        assert load(env_file=env_path).DEDUP_ENABLED is False

    def test_a_real_env_var_wins_over_the_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DEDUP_ENABLED", "true")
        env_path = write_env(tmp_path, "DEDUP_ENABLED=false\n")
        assert load(env_file=env_path).DEDUP_ENABLED is True

    def test_it_is_a_pack_key_and_an_env_example_key(self):
        assert "DEDUP_ENABLED" in gen_env_example.keys_from_pack()
        example = (pathlib.Path(__file__).resolve().parents[2] / ".env.example").read_text(
            encoding="utf-8"
        )
        assert "\nDEDUP_ENABLED=" in example


_SOAR_SWITCHES = ("PULL_ENABLED", "AUTOCLOSE_ENABLED", "ENRICHMENT_ENABLED")


@pytest.mark.parametrize("key", _SOAR_SWITCHES)
class TestSoarIntakeSwitches:
    """P12-T01 / DEC-207: three bool keys next to `DEDUP_ENABLED`, every one defaulting to
    `true`, so a `.env` that names none of them behaves exactly as before; the Owner turns one
    off in the live `.env` when the SOAR stream owns that step. Parsed by the same `as_bool`
    as `DEDUP_ENABLED`: anything but a recognised spelling stops the start-up naming the key."""

    def test_the_key_is_a_bool_config_field_defaulting_to_true(self, key):
        field = {f.name: f for f in dataclasses.fields(Config)}[key]
        assert field.default is True
        assert getattr(Config(), key) is True

    def test_default_is_true_when_unset(self, monkeypatch, key):
        monkeypatch.delenv(key, raising=False)
        assert getattr(load(env_file="/dev/null"), key) is True

    def test_empty_value_falls_back_to_the_default_true(self, monkeypatch, key):
        monkeypatch.setenv(key, "")
        assert getattr(load(env_file="/dev/null"), key) is True

    @pytest.mark.parametrize("raw", ["false", "False", "FALSE", "0", "no", "off", " false "])
    def test_false_spellings_turn_it_off(self, monkeypatch, key, raw):
        monkeypatch.setenv(key, raw)
        assert getattr(load(env_file="/dev/null"), key) is False

    @pytest.mark.parametrize("raw", ["true", "True", "TRUE", "1", "yes", "on"])
    def test_true_spellings_keep_it_on(self, monkeypatch, key, raw):
        monkeypatch.setenv(key, raw)
        assert getattr(load(env_file="/dev/null"), key) is True

    @pytest.mark.parametrize("raw", ["flase", "2", "enabled", "nope"])
    def test_anything_else_raises_naming_the_key_never_a_silent_default(
        self, monkeypatch, key, raw
    ):
        monkeypatch.setenv(key, raw)
        with pytest.raises(ConfigError, match=key):
            load(env_file="/dev/null")

    def test_dotenv_file_is_read_like_every_other_key(self, tmp_path, monkeypatch, key):
        monkeypatch.delenv(key, raising=False)
        env_path = write_env(tmp_path, f"{key}=false  # DEC-207, live\n")
        assert getattr(load(env_file=env_path), key) is False

    def test_a_real_env_var_wins_over_the_file(self, tmp_path, monkeypatch, key):
        monkeypatch.setenv(key, "true")
        env_path = write_env(tmp_path, f"{key}=false\n")
        assert getattr(load(env_file=env_path), key) is True

    def test_one_switch_does_not_move_the_others(self, tmp_path, monkeypatch, key):
        for other in (*_SOAR_SWITCHES, "DEDUP_ENABLED"):
            monkeypatch.delenv(other, raising=False)
        env_path = write_env(tmp_path, f"{key}=false\n")
        cfg = load(env_file=env_path)
        for other in (*_SOAR_SWITCHES, "DEDUP_ENABLED"):
            assert getattr(cfg, other) is (other != key), other

    def test_it_is_a_pack_key_and_an_env_example_key(self, key):
        assert key in gen_env_example.keys_from_pack()
        example = (pathlib.Path(__file__).resolve().parents[2] / ".env.example").read_text(
            encoding="utf-8"
        )
        assert f"\n{key}=true" in example


def test_with_no_soar_switch_named_the_config_is_the_one_before_dec_207(monkeypatch):
    """A `.env` that names none of the four flags: all of them on, which is `a0398c2`'s behaviour."""
    for key in (*_SOAR_SWITCHES, "DEDUP_ENABLED"):
        monkeypatch.delenv(key, raising=False)
    cfg = load(env_file="/dev/null")
    assert (cfg.DEDUP_ENABLED, cfg.PULL_ENABLED, cfg.AUTOCLOSE_ENABLED, cfg.ENRICHMENT_ENABLED) == (
        True,
        True,
        True,
        True,
    )


_RAG_SWITCHES = ("RAG_ENABLED", "KNOWLEDGE_DRAFT_ENABLED")
_RAG_INTS = {
    "RAG_TRIAGE_DELAY_S": 45,
    "RAG_CASE_REFRESH_H": 24,
    "RAG_HISTORY_DAYS": 90,
    "RAG_MONTHLY_USD_CAP": 3,
    "KNOWLEDGE_QUEUE_MAX": 200,
}
_RAG_KEYS = (*_RAG_SWITCHES, "RAG_MODEL", *_RAG_INTS)


def _clear_rag_env(monkeypatch):
    for key in _RAG_KEYS:
        monkeypatch.delenv(key, raising=False)


def _example_text():
    return (pathlib.Path(__file__).resolve().parents[2] / ".env.example").read_text(
        encoding="utf-8"
    )


class TestLearnedKnowledgeKeys:
    """P13-T01 / DEC-210: eight `.env`-only keys. The two switches default to `false`, so merging
    the feature changes nothing until the Owner turns one on; the five numbers are non-negative
    (a negative delay, window or cap has no meaning and must stop the start-up, never be clamped
    quietly); `RAG_MODEL` is empty, which the ranking agent reads as `LLM_MODEL_PROPOSER`."""

    def test_the_eight_keys_are_config_fields_with_the_global_constraints_defaults(self):
        fields = {f.name: f for f in dataclasses.fields(Config)}
        assert fields["RAG_ENABLED"].default is False
        assert fields["KNOWLEDGE_DRAFT_ENABLED"].default is False
        assert fields["RAG_MODEL"].default == ""
        for key, default in _RAG_INTS.items():
            assert fields[key].default == default and type(fields[key].default) is int, key
        assert len(_RAG_KEYS) == 8

    def test_load_with_nothing_named_gives_the_defaults(self, monkeypatch):
        _clear_rag_env(monkeypatch)
        cfg = load(env_file="/dev/null")
        assert (cfg.RAG_ENABLED, cfg.KNOWLEDGE_DRAFT_ENABLED) == (False, False)
        assert cfg.RAG_MODEL == ""
        assert {key: getattr(cfg, key) for key in _RAG_INTS} == _RAG_INTS

    def test_empty_values_fall_through_to_the_defaults(self, monkeypatch):
        for key in _RAG_KEYS:
            monkeypatch.setenv(key, "")
        cfg = load(env_file="/dev/null")
        assert (cfg.RAG_ENABLED, cfg.KNOWLEDGE_DRAFT_ENABLED, cfg.RAG_MODEL) == (False, False, "")
        assert {key: getattr(cfg, key) for key in _RAG_INTS} == _RAG_INTS

    @pytest.mark.parametrize("key", _RAG_SWITCHES)
    @pytest.mark.parametrize("raw", ["true", "True", "TRUE", "1", "yes", "on"])
    def test_true_spellings_turn_a_switch_on(self, monkeypatch, key, raw):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv(key, raw)
        assert getattr(load(env_file="/dev/null"), key) is True

    @pytest.mark.parametrize("key", _RAG_SWITCHES)
    @pytest.mark.parametrize("raw", ["false", "False", "FALSE", "0", "no", "off", " false "])
    def test_false_spellings_keep_a_switch_off(self, monkeypatch, key, raw):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv(key, raw)
        assert getattr(load(env_file="/dev/null"), key) is False

    @pytest.mark.parametrize("key", _RAG_SWITCHES)
    @pytest.mark.parametrize("raw", ["flase", "2", "enabled", "nope"])
    def test_anything_else_raises_naming_the_switch(self, monkeypatch, key, raw):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv(key, raw)
        with pytest.raises(ConfigError, match=key):
            load(env_file="/dev/null")

    @pytest.mark.parametrize("key", _RAG_SWITCHES)
    def test_one_switch_does_not_move_the_other(self, tmp_path, monkeypatch, key):
        _clear_rag_env(monkeypatch)
        cfg = load(env_file=write_env(tmp_path, f"{key}=true\n"))
        assert {k: getattr(cfg, k) for k in _RAG_SWITCHES} == {k: (k == key) for k in _RAG_SWITCHES}

    @pytest.mark.parametrize("key", _RAG_INTS)
    def test_an_int_key_reads_a_value_with_underscores(self, monkeypatch, key):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv(key, "1_000")
        assert getattr(load(env_file="/dev/null"), key) == 1000

    @pytest.mark.parametrize("key", _RAG_INTS)
    def test_zero_is_a_value_not_a_refusal(self, monkeypatch, key):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv(key, "0")
        assert getattr(load(env_file="/dev/null"), key) == 0

    @pytest.mark.parametrize("key", _RAG_INTS)
    @pytest.mark.parametrize("raw", ["-1", "-45", "-1_000"])
    def test_a_negative_int_raises_naming_the_key(self, monkeypatch, key, raw):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv(key, raw)
        with pytest.raises(ConfigError, match=key):
            load(env_file="/dev/null")

    @pytest.mark.parametrize("key", _RAG_INTS)
    def test_a_negative_int_in_the_dotenv_file_is_refused_too(self, tmp_path, monkeypatch, key):
        _clear_rag_env(monkeypatch)
        with pytest.raises(ConfigError, match=key):
            load(env_file=write_env(tmp_path, f"{key}=-3\n"))

    @pytest.mark.parametrize("key", _RAG_INTS)
    def test_not_a_number_raises_naming_the_key(self, monkeypatch, key):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv(key, "soon")
        with pytest.raises(ConfigError, match=key):
            load(env_file="/dev/null")

    def test_rag_model_is_a_plain_string_and_may_name_a_model(self, tmp_path, monkeypatch):
        _clear_rag_env(monkeypatch)
        cfg = load(env_file=write_env(tmp_path, "RAG_MODEL=deepseek-v4-flash  # own model\n"))
        assert cfg.RAG_MODEL == "deepseek-v4-flash"

    def test_rag_model_does_not_follow_the_proposer_in_config(self, tmp_path, monkeypatch):
        """Unlike `LLM_MODEL_VERIFIER`, the key stays empty when unset: the ranking agent
        (T03) reads empty as the proposer's model, so `.env.example` can show the key bare."""
        _clear_rag_env(monkeypatch)
        monkeypatch.delenv("LLM_MODEL_PROPOSER", raising=False)
        cfg = load(env_file=write_env(tmp_path, "LLM_MODEL_PROPOSER=deepseek-v4-flash\n"))
        assert cfg.RAG_MODEL == ""

    def test_a_real_env_var_wins_over_the_file(self, tmp_path, monkeypatch):
        _clear_rag_env(monkeypatch)
        monkeypatch.setenv("RAG_ENABLED", "true")
        monkeypatch.setenv("RAG_HISTORY_DAYS", "30")
        cfg = load(env_file=write_env(tmp_path, "RAG_ENABLED=false\nRAG_HISTORY_DAYS=7\n"))
        assert (cfg.RAG_ENABLED, cfg.RAG_HISTORY_DAYS) == (True, 30)

    def test_the_secret_redaction_does_not_touch_the_new_keys(self, monkeypatch):
        _clear_rag_env(monkeypatch)
        dumped = load(env_file="/dev/null").dump()
        for key in _RAG_KEYS:
            assert dumped[key] != "***", key

    @pytest.mark.parametrize("key", _RAG_KEYS)
    def test_each_key_is_a_pack_key_and_an_env_example_line(self, key):
        assert key in gen_env_example.keys_from_pack()
        assert f"\n{key}=" in _example_text()

    @pytest.mark.parametrize("key", _RAG_SWITCHES)
    def test_env_example_shows_a_switch_off(self, key):
        assert f"\n{key}=false" in _example_text()

    @pytest.mark.parametrize(("key", "default"), list(_RAG_INTS.items()))
    def test_env_example_shows_each_number_at_its_default(self, key, default):
        assert f"\n{key}={default}" in _example_text()


#: P14-T04 / DEC-213: the eleven keys of Part B (Voyage embeddings and rerank, the independent
#: pgvector), in context pack §6.3's order, with the default each one has when nothing names it.
_VOYAGE_DEFAULTS = {
    "VOYAGE_API_KEY": "",
    "VOYAGE_BASE_URL": "https://api.voyageai.com/v1",
    "RAG_EMBED_MODEL": "voyage-4",
    "RAG_EMBED_DIMS": 1024,
    "RAG_RERANK_MODEL": "rerank-2.5",
    "RAG_MIN_SCORE": 0.50,
    "RAG_LEVEL_GIONG": 0.65,
    "RAG_LEVEL_RAT_GIONG": 0.80,
    "VOYAGE_PRICE_EMBED_PER_M": 0.06,
    "VOYAGE_PRICE_RERANK_PER_M": 0.05,
    "VECTOR_DATABASE_URL": "",
}
_VOYAGE_THRESHOLDS = ("RAG_MIN_SCORE", "RAG_LEVEL_GIONG", "RAG_LEVEL_RAT_GIONG")
_VOYAGE_DIMS = (256, 512, 1024, 2048)
#: Planted values that must never reach a `repr`, a `dump()` or an error message.
_VOYAGE_KEY_SENTINEL = "pa-VOYAGE-SENTINEL-4242"
_VECTOR_DSN_SENTINEL = "postgresql://vector:VECTOR-PW-SENTINEL@vectordb:5432/vectors"


def _clear_voyage_env(monkeypatch):
    for key in _VOYAGE_DEFAULTS:
        monkeypatch.delenv(key, raising=False)


def _env_example_value(key):
    """The value `.env.example` shows for `key`, a trailing ` # comment` stripped."""
    for line in _example_text().splitlines():
        if line.startswith(f"{key}="):
            return line.partition("=")[2].split("  #")[0].strip()
    raise AssertionError(f"{key} is not a line of .env.example")


class TestVoyageVectorKeys:
    """P14-T04 / DEC-213: eleven `.env`-only keys. Their defaults are the plan's key table, verbatim.
    The three thresholds are provisional until calibration but must stay in order, and the embedding
    size is one of the four Voyage serves; `VOYAGE_API_KEY` and `VECTOR_DATABASE_URL` are secrets
    (the second carries the vector database's password)."""

    def test_the_eleven_keys_are_config_fields_with_the_key_tables_defaults(self):
        fields = {f.name: f for f in dataclasses.fields(Config)}
        assert len(_VOYAGE_DEFAULTS) == 11
        for key, default in _VOYAGE_DEFAULTS.items():
            assert fields[key].default == default, key
            assert type(fields[key].default) is type(default), key

    def test_load_with_nothing_named_gives_the_defaults(self, monkeypatch):
        _clear_voyage_env(monkeypatch)
        cfg = load(env_file="/dev/null")
        assert {key: getattr(cfg, key) for key in _VOYAGE_DEFAULTS} == _VOYAGE_DEFAULTS

    def test_empty_values_fall_through_to_the_defaults(self, monkeypatch):
        for key in _VOYAGE_DEFAULTS:
            monkeypatch.setenv(key, "")
        cfg = load(env_file="/dev/null")
        assert {key: getattr(cfg, key) for key in _VOYAGE_DEFAULTS} == _VOYAGE_DEFAULTS

    def test_each_key_is_read_from_the_dotenv_file(self, tmp_path, monkeypatch):
        _clear_voyage_env(monkeypatch)
        text = "\n".join(
            [
                f"VOYAGE_API_KEY={_VOYAGE_KEY_SENTINEL}",
                "VOYAGE_BASE_URL=http://voyage.test/v1",
                "RAG_EMBED_MODEL=voyage-4-lite",
                "RAG_EMBED_DIMS=512",
                "RAG_RERANK_MODEL=rerank-3",
                "RAG_MIN_SCORE=0.40",
                "RAG_LEVEL_GIONG=0.60",
                "RAG_LEVEL_RAT_GIONG=0.90",
                "VOYAGE_PRICE_EMBED_PER_M=0.12",
                "VOYAGE_PRICE_RERANK_PER_M=0.08",
                f"VECTOR_DATABASE_URL={_VECTOR_DSN_SENTINEL}",
            ]
        )
        cfg = load(env_file=write_env(tmp_path, text + "\n"))
        assert cfg.VOYAGE_API_KEY == _VOYAGE_KEY_SENTINEL
        assert cfg.VOYAGE_BASE_URL == "http://voyage.test/v1"
        assert (cfg.RAG_EMBED_MODEL, cfg.RAG_EMBED_DIMS, cfg.RAG_RERANK_MODEL) == (
            "voyage-4-lite",
            512,
            "rerank-3",
        )
        assert (cfg.RAG_MIN_SCORE, cfg.RAG_LEVEL_GIONG, cfg.RAG_LEVEL_RAT_GIONG) == (
            0.40,
            0.60,
            0.90,
        )
        assert (cfg.VOYAGE_PRICE_EMBED_PER_M, cfg.VOYAGE_PRICE_RERANK_PER_M) == (0.12, 0.08)
        assert cfg.VECTOR_DATABASE_URL == _VECTOR_DSN_SENTINEL

    def test_a_real_env_var_wins_over_the_file(self, tmp_path, monkeypatch):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_EMBED_DIMS", "256")
        cfg = load(env_file=write_env(tmp_path, "RAG_EMBED_DIMS=2048\n"))
        assert cfg.RAG_EMBED_DIMS == 256

    # -- the embedding size ---------------------------------------------------------------------

    @pytest.mark.parametrize("dims", _VOYAGE_DIMS)
    def test_each_size_voyage_serves_is_accepted(self, monkeypatch, dims):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_EMBED_DIMS", str(dims))
        assert load(env_file="/dev/null").RAG_EMBED_DIMS == dims

    @pytest.mark.parametrize("raw", ["1000", "768", "0", "-1024", "4096", "128", "1_025"])
    def test_any_other_size_raises_naming_the_key(self, monkeypatch, raw):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_EMBED_DIMS", raw)
        with pytest.raises(ConfigError, match="RAG_EMBED_DIMS") as caught:
            load(env_file="/dev/null")
        assert "256" in str(caught.value) and "2048" in str(caught.value)

    def test_a_size_in_the_dotenv_file_is_checked_too(self, tmp_path, monkeypatch):
        _clear_voyage_env(monkeypatch)
        with pytest.raises(ConfigError, match="RAG_EMBED_DIMS"):
            load(env_file=write_env(tmp_path, "RAG_EMBED_DIMS=1000\n"))

    def test_a_size_that_is_not_a_number_raises_naming_the_key(self, monkeypatch):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_EMBED_DIMS", "wide")
        with pytest.raises(ConfigError, match="RAG_EMBED_DIMS"):
            load(env_file="/dev/null")

    # -- the three thresholds -------------------------------------------------------------------

    def test_a_minimum_above_the_giong_level_raises_naming_all_three_keys(self, monkeypatch):
        """The brief's case: `RAG_MIN_SCORE=0.9` against the default `RAG_LEVEL_GIONG` of 0.65."""
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_MIN_SCORE", "0.9")
        with pytest.raises(ConfigError) as caught:
            load(env_file="/dev/null")
        for key in _VOYAGE_THRESHOLDS:
            assert key in str(caught.value), key

    @pytest.mark.parametrize(
        ("minimum", "giong", "rat_giong"),
        [
            ("0.70", "0.65", "0.80"),  # MIN above GIONG
            ("0.50", "0.85", "0.80"),  # GIONG above RAT_GIONG
            ("0.50", "0.65", "1.01"),  # RAT_GIONG above 1
            ("-0.01", "0.65", "0.80"),  # MIN below 0
            ("0.90", "0.70", "0.60"),  # fully reversed
            ("nan", "0.65", "0.80"),  # no order at all
            ("0.50", "0.65", "inf"),  # not a score
        ],
    )
    def test_thresholds_out_of_order_or_out_of_range_raise(
        self, monkeypatch, minimum, giong, rat_giong
    ):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_MIN_SCORE", minimum)
        monkeypatch.setenv("RAG_LEVEL_GIONG", giong)
        monkeypatch.setenv("RAG_LEVEL_RAT_GIONG", rat_giong)
        with pytest.raises(ConfigError, match="RAG_MIN_SCORE"):
            load(env_file="/dev/null")

    @pytest.mark.parametrize(
        ("minimum", "giong", "rat_giong"),
        [
            ("0.50", "0.65", "0.80"),  # the defaults
            ("0.70", "0.70", "0.70"),  # equal is in order
            ("0", "0", "0"),  # the edge
            ("1", "1", "1"),  # the other edge
            ("0", "0.5", "1"),  # the widest spread
            ("0.0", "0.30", "0.30"),
        ],
    )
    def test_thresholds_in_order_inside_zero_to_one_are_accepted(
        self, monkeypatch, minimum, giong, rat_giong
    ):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_MIN_SCORE", minimum)
        monkeypatch.setenv("RAG_LEVEL_GIONG", giong)
        monkeypatch.setenv("RAG_LEVEL_RAT_GIONG", rat_giong)
        cfg = load(env_file="/dev/null")
        assert (cfg.RAG_MIN_SCORE, cfg.RAG_LEVEL_GIONG, cfg.RAG_LEVEL_RAT_GIONG) == (
            float(minimum),
            float(giong),
            float(rat_giong),
        )

    def test_the_order_is_judged_across_tiers(self, tmp_path, monkeypatch):
        """One threshold from the environment, the others from the file or the defaults."""
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("RAG_LEVEL_RAT_GIONG", "0.55")
        with pytest.raises(ConfigError, match="RAG_LEVEL_RAT_GIONG"):
            load(env_file=write_env(tmp_path, "RAG_LEVEL_GIONG=0.70\n"))

    @pytest.mark.parametrize("key", _VOYAGE_THRESHOLDS)
    def test_a_threshold_that_is_not_a_number_raises_naming_the_key(self, monkeypatch, key):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv(key, "high")
        with pytest.raises(ConfigError, match=key):
            load(env_file="/dev/null")

    # -- the secrets ----------------------------------------------------------------------------

    def test_repr_hides_the_voyage_key_and_the_vector_dsn(self, monkeypatch):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("VOYAGE_API_KEY", _VOYAGE_KEY_SENTINEL)
        monkeypatch.setenv("VECTOR_DATABASE_URL", _VECTOR_DSN_SENTINEL)
        cfg = load(env_file="/dev/null")
        text = repr(cfg) + str(cfg) + repr(cfg.dump()) + str(cfg.dump())
        for secret in (_VOYAGE_KEY_SENTINEL, "VOYAGE-SENTINEL", _VECTOR_DSN_SENTINEL):
            assert secret not in text, secret
        assert "VECTOR-PW-SENTINEL" not in text
        assert "VOYAGE_API_KEY='***'" in repr(cfg)
        assert "VECTOR_DATABASE_URL='***'" in repr(cfg)

    def test_the_other_nine_keys_are_shown(self, monkeypatch):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("VOYAGE_API_KEY", _VOYAGE_KEY_SENTINEL)
        monkeypatch.setenv("VECTOR_DATABASE_URL", _VECTOR_DSN_SENTINEL)
        dumped = load(env_file="/dev/null").dump()
        for key, default in _VOYAGE_DEFAULTS.items():
            if key not in ("VOYAGE_API_KEY", "VECTOR_DATABASE_URL"):
                assert dumped[key] == default, key

    def test_an_empty_secret_is_not_masked_into_a_false_positive(self, monkeypatch):
        _clear_voyage_env(monkeypatch)
        dumped = load(env_file="/dev/null").dump()
        assert dumped["VOYAGE_API_KEY"] == "" and dumped["VECTOR_DATABASE_URL"] == ""

    def test_a_refusal_prints_no_secret(self, monkeypatch):
        _clear_voyage_env(monkeypatch)
        monkeypatch.setenv("VOYAGE_API_KEY", _VOYAGE_KEY_SENTINEL)
        monkeypatch.setenv("VECTOR_DATABASE_URL", _VECTOR_DSN_SENTINEL)
        monkeypatch.setenv("RAG_EMBED_DIMS", "1000")
        with pytest.raises(ConfigError) as caught:
            load(env_file="/dev/null")
        assert "SENTINEL" not in str(caught.value)
        monkeypatch.setenv("RAG_EMBED_DIMS", "1024")
        monkeypatch.setenv("RAG_MIN_SCORE", "0.99")
        with pytest.raises(ConfigError) as caught:
            load(env_file="/dev/null")
        assert "SENTINEL" not in str(caught.value)

    # -- where the keys live --------------------------------------------------------------------

    def test_they_are_env_keys_only_never_web_settings(self):
        """`infra.settings.KEYS` is the whole list the admin may change on the web (DEC-200)."""
        from app.infra import settings

        assert set(_VOYAGE_DEFAULTS).isdisjoint(settings.KEYS)
        assert set(_VOYAGE_DEFAULTS).isdisjoint(settings.BOUNDS)

    @pytest.mark.parametrize("key", list(_VOYAGE_DEFAULTS))
    def test_each_key_is_a_pack_key_and_an_env_example_line(self, key):
        assert key in gen_env_example.keys_from_pack()
        assert f"\n{key}=" in _example_text()

    def test_the_pack_lists_them_after_the_learned_knowledge_keys_in_the_tables_order(self):
        pack = gen_env_example.keys_from_pack()
        start = pack.index("KNOWLEDGE_QUEUE_MAX") + 1
        assert pack[start : start + len(_VOYAGE_DEFAULTS)] == list(_VOYAGE_DEFAULTS)

    @pytest.mark.parametrize(
        ("key", "default"), [(k, v) for k, v in _VOYAGE_DEFAULTS.items() if "KEY" not in k]
    )
    def test_env_example_shows_each_key_at_its_default(self, key, default):
        shown = _env_example_value(key)
        assert type(default)(shown) == default, (key, shown)

    @pytest.mark.parametrize("key", ["VOYAGE_API_KEY", "VECTOR_DATABASE_URL"])
    def test_env_example_carries_no_secret(self, key):
        assert _env_example_value(key) == ""

    def test_gen_env_example_check_exits_zero(self):
        """`make lint` runs `scripts/gen_env_example.py --check`; here the same check is a test, so
        `.env.example` drifting from §6.3 (a key added to one and not the other) is red under `make test`.
        """
        script = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "gen_env_example.py"
        run = subprocess.run(
            [sys.executable, str(script), "--check"], capture_output=True, text=True, check=False
        )
        assert run.returncode == 0, run.stderr[-400:]

    def test_an_empty_voyage_key_is_said_to_fail_the_lookup_with_kind_auth_in_all_four_places(self):
        """DEC-213, the Director's ruling (P14-T04 fix round 1, F3): with the RAG on, an empty
        `VOYAGE_API_KEY` makes the lookup `failed` with `failure_kind='auth'`, sends no request and the UI
        says so. It is not "skipped, as with no model". Words only: T05 and T06 implement it."""
        root = pathlib.Path(__file__).resolve().parents[2]
        config_py = (root / "backend" / "app" / "infra" / "config.py").read_text(encoding="utf-8")
        places = {
            "config.py": config_py.split("VOYAGE_API_KEY: str")[0].rsplit("DEC-213 (P14", 1)[1],
            "context pack §6.3": next(
                ln
                for ln in (root / "docs" / "plan" / "00-context-pack.md")
                .read_text(encoding="utf-8")
                .splitlines()
                if ln.startswith("VOYAGE_API_KEY(")
            ),
            ".env.example": next(
                ln for ln in _example_text().splitlines() if ln.startswith("VOYAGE_API_KEY=")
            ),
            "runbook key row": next(
                ln
                for ln in (root / "docs" / "runbook.md").read_text(encoding="utf-8").splitlines()
                if ln.startswith("| `VOYAGE_API_KEY` |")
            ),
        }
        for name, text in places.items():
            flat = " ".join(text.split())
            assert "skipped" not in flat and "as with no model" not in flat, name
            assert "auth" in flat and ("failed" in flat or "fails" in flat), name
            assert "no request" in flat, name

    def test_env_example_has_89_keys_and_names_the_compose_only_password_in_a_comment(self):
        lines = _example_text().splitlines()
        keys = [
            ln.partition("=")[0].strip() for ln in lines if re.match(r"^\s*[A-Z][A-Z0-9_]{2,}=", ln)
        ]
        assert len(keys) == len(set(keys)) == 89  # 88 + TRIAGE_RAG_FP_BELOW_PCT (DEC-219)
        assert (
            "VECTOR_DB_PASSWORD" not in keys
        )  # Compose-only, like APP_RW_PASSWORD, and a comment here
        comment = [ln for ln in lines if ln.startswith("#") and "VECTOR_DB_PASSWORD" in ln]
        assert comment, ".env.example does not say VECTOR_DB_PASSWORD is a Compose-only variable"
        text = " ".join(comment)
        assert "Compose" in text and "DEC-213" in text


class TestStartupAssertion:
    def test_max_payload_not_greater_than_raw_log_raises_naming_both_keys(self, monkeypatch):
        monkeypatch.setenv("MAX_PAYLOAD_BYTES", "1000")
        with pytest.raises(ConfigError) as exc_info:
            load(env_file="/dev/null")
        message = str(exc_info.value)
        assert "MAX_PAYLOAD_BYTES" in message
        assert "RAW_LOG_MAX_BYTES" in message

    def test_equal_sizes_also_violate_the_assertion(self, monkeypatch):
        monkeypatch.setenv("MAX_PAYLOAD_BYTES", "1_024_000")
        monkeypatch.setenv("RAW_LOG_MAX_BYTES", "1_024_000")
        with pytest.raises(ConfigError, match="RAW_LOG_MAX_BYTES"):
            load(env_file="/dev/null")

    def test_default_sizes_satisfy_the_assertion(self, monkeypatch):
        monkeypatch.delenv("MAX_PAYLOAD_BYTES", raising=False)
        monkeypatch.delenv("RAW_LOG_MAX_BYTES", raising=False)
        c = load(env_file="/dev/null")
        assert c.MAX_PAYLOAD_BYTES > c.RAW_LOG_MAX_BYTES


class TestSecretsNeverPrint:
    def test_repr_redacts_known_secrets(self, monkeypatch):
        monkeypatch.setenv("LLM_API_KEY", "sk-test-SECRET123")
        monkeypatch.setenv("INDEXER_PASSWORD", "pw-SECRET456")
        c = load(env_file="/dev/null")
        text = repr(c) + repr(c.dump())
        assert "SECRET123" not in text
        assert "SECRET456" not in text

    def test_dump_redacts_known_secrets(self, monkeypatch):
        monkeypatch.setenv("JWT_SECRET", "jwt-SECRET789")
        monkeypatch.setenv("WEBHOOK_API_KEY", "whk-SECRETABC")
        monkeypatch.setenv("NOTIFY_TELEGRAM_BOT_TOKEN", "tg-SECRETDEF")
        c = load(env_file="/dev/null")
        dumped = str(c.dump())
        for secret in ("SECRET789", "SECRETABC", "SECRETDEF"):
            assert secret not in dumped

    def test_dump_is_a_dict_covering_every_field(self):
        c = load(env_file="/dev/null")
        dumped = c.dump()
        assert isinstance(dumped, dict)
        assert {f.name for f in dataclasses.fields(Config)} == set(dumped.keys())

    def test_empty_secret_is_not_masked_into_a_false_positive(self, monkeypatch):
        monkeypatch.delenv("JWT_SECRET", raising=False)
        c = load(env_file="/dev/null")
        assert c.dump()["JWT_SECRET"] == ""


class TestEnvFilePrecedence:
    def test_real_env_var_wins_over_dotenv_file(self, tmp_path, monkeypatch):
        env_path = write_env(tmp_path, "PULL_PAGE=111\n")
        monkeypatch.setenv("PULL_PAGE", "222")
        c = load(env_file=env_path)
        assert c.PULL_PAGE == 222

    def test_dotenv_file_used_when_env_var_absent(self, tmp_path, monkeypatch):
        env_path = write_env(tmp_path, "PULL_PAGE=333\n")
        monkeypatch.delenv("PULL_PAGE", raising=False)
        c = load(env_file=env_path)
        assert c.PULL_PAGE == 333

    def test_blank_lines_and_whole_line_comments_are_skipped(self, tmp_path, monkeypatch):
        env_path = write_env(tmp_path, "\n# a comment\n\nPULL_PAGE=444\n")
        monkeypatch.delenv("PULL_PAGE", raising=False)
        c = load(env_file=env_path)
        assert c.PULL_PAGE == 444

    def test_trailing_comment_stripped_only_with_preceding_whitespace(self, tmp_path, monkeypatch):
        env_path = write_env(tmp_path, "DISPLAY_TZ=UTC  # a trailing comment\n")
        monkeypatch.delenv("DISPLAY_TZ", raising=False)
        c = load(env_file=env_path)
        assert c.DISPLAY_TZ == "UTC"

    def test_hash_with_no_preceding_whitespace_survives_in_value(self, tmp_path, monkeypatch):
        env_path = write_env(tmp_path, "JWT_SECRET=abc#def\n")
        monkeypatch.delenv("JWT_SECRET", raising=False)
        c = load(env_file=env_path)
        assert c.JWT_SECRET == "abc#def"

    def test_last_assignment_wins(self, tmp_path, monkeypatch):
        env_path = write_env(tmp_path, "PULL_PAGE=1\nPULL_PAGE=2\nPULL_PAGE=3\n")
        monkeypatch.delenv("PULL_PAGE", raising=False)
        c = load(env_file=env_path)
        assert c.PULL_PAGE == 3


class TestIntAndFloatParsing:
    def test_integer_with_underscores(self, monkeypatch):
        monkeypatch.setenv("MAX_PAYLOAD_BYTES", "3_000_000")
        c = load(env_file="/dev/null")
        assert c.MAX_PAYLOAD_BYTES == 3_000_000

    def test_invalid_integer_raises_naming_the_key(self, monkeypatch):
        monkeypatch.setenv("PULL_PAGE", "not-a-number")
        with pytest.raises(ConfigError, match="PULL_PAGE"):
            load(env_file="/dev/null")

    def test_invalid_float_raises_naming_the_key(self, monkeypatch):
        monkeypatch.setenv("EVAL_BLIND_FRACTION", "not-a-float")
        with pytest.raises(ConfigError, match="EVAL_BLIND_FRACTION"):
            load(env_file="/dev/null")


class TestConfigIsFrozen:
    def test_setting_a_field_after_construction_raises(self):
        c = load(env_file="/dev/null")
        with pytest.raises(dataclasses.FrozenInstanceError):
            c.PULL_PAGE = 1


class TestNoIoAtImportTime:
    def test_no_clock_db_or_network_calls_in_source(self):
        backend_root = pathlib.Path(__file__).resolve().parents[1]
        source = (backend_root / "app" / "infra" / "config.py").read_text()
        for forbidden in ("datetime.now(", "time.time(", "psycopg.connect", "httpx.Client("):
            assert forbidden not in source, f"found {forbidden!r} in config.py"
