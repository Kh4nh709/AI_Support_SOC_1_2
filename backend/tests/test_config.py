"""Unit tests for app.infra.config — pure, no clock/DB/network."""

from __future__ import annotations

import dataclasses
import pathlib
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
