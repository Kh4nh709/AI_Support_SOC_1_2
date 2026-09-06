"""The context pack §6.3 configuration constants, each overridable by an environment variable.

Precedence per key: a real environment variable, then `.env` (git-ignored, absent
in a fresh worktree), then §6.3's documented default. An unset-or-empty value at
either of the first two tiers falls through to the next tier — an empty override
is never distinguished from an absent one. `Config` is a frozen dataclass whose
field set is exactly `scripts/gen_env_example.py`'s `keys_from_pack()` (the one
extractor of §6.3's key set, DEC-027); derived values such as `llm_enabled` are
`@property`s, not fields, so they never appear in that set.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from pathlib import Path

from app.infra.errors import ConfigError

_TRAILING_COMMENT_RE = re.compile(r"\s+#.*$")

# §5 of phase-1: a payload larger than this is rejected before a raw log within
# it could ever be truncated to RAW_LOG_MAX_BYTES. Named via variables, not
# spelled out at the raise site, so the source line itself does not also carry
# the literal key names — only the rendered message should.
_MAX_PAYLOAD_KEY = "MAX_PAYLOAD_BYTES"
_RAW_LOG_KEY = "RAW_LOG_MAX_BYTES"

# "strings and secrets" (design note 3): redacted by __repr__ and dump().
_SECRET_FIELDS = frozenset(
    {
        "INDEXER_PASSWORD",
        "LLM_API_KEY",
        "JWT_SECRET",
        "WEBHOOK_API_KEY",
        "NOTIFY_TELEGRAM_BOT_TOKEN",
        "NOTIFY_TELEGRAM_CHAT_ID",
    }
)

_LLM_THINKING_VALUES = ("enabled", "disabled")


def _read_env_file(path: Path) -> dict[str, str]:
    """`KEY=value` lines; blank lines and lines whose first non-space character
    is `#` are skipped; a trailing ` # comment` is stripped only when whitespace
    precedes the `#` (so a `#` inside a password survives); the last assignment
    for a key wins."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            continue
        values[key.strip()] = _TRAILING_COMMENT_RE.sub("", value).strip()
    return values


def _parse_int(key: str, raw: str) -> int:
    try:
        return int(raw.replace("_", ""))
    except ValueError as exc:
        raise ConfigError(f"{key}: not a valid integer: {raw!r}") from exc


def _parse_float(key: str, raw: str) -> float:
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{key}: not a valid float: {raw!r}") from exc


def _parse_json_list(key: str, raw: str, item_type: type) -> list:
    """DEC-007 item 2: bad JSON, or JSON that is not a list of `item_type`, is a
    `ConfigError` naming `key` — never a silent fallback (an empty/unset value is
    handled by the caller before this is reached)."""
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{key}: not valid JSON: {raw!r}") from exc
    valid = isinstance(value, list) and all(
        isinstance(item, item_type) and not isinstance(item, bool) for item in value
    )
    if not valid:
        raise ConfigError(f"{key}: must be a JSON list of {item_type.__name__}: {raw!r}")
    return value


def _parse_enum(key: str, raw: str, allowed: tuple[str, ...]) -> str:
    if raw not in allowed:
        raise ConfigError(f"{key}: must be one of {'|'.join(allowed)}, got {raw!r}")
    return raw


@dataclasses.dataclass(frozen=True, repr=False)
class Config:
    DATABASE_URL: str = ""
    DATABASE_URL_OWNER: str = "postgresql:///soc_dev"
    TEST_DATABASE_URL: str = "postgresql:///soc_test"
    MAX_PAYLOAD_BYTES: int = 2_097_152
    RAW_LOG_MAX_BYTES: int = 1_024_000
    PROMPT_LOG_MAX_BYTES: int = 32_768
    DEDUP_IDLE_GAP_MINUTES: int = 15
    MAX_CLUSTER_AGE_HOURS: int = 4
    MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES: int = 30
    MAX_CLUSTER_SIZE: int = 1000
    INDEXER_URL: str = ""
    INDEXER_USER: str = ""
    INDEXER_PASSWORD: str = ""
    INDEXER_CA: str = ""
    INDEXER_INDEX: str = "wazuh-alerts-*"
    PULL_INTERVAL_S: int = 60
    PULL_OVERLAP_S: int = 60
    PULL_PAGE: int = 500
    PULL_START: str = "2026-08-01"
    HEARTBEAT_RULE_ID: str = "100999"
    HEARTBEAT_MAX_AGE_MIN: int = 30
    SILENCE_WARN_HOURS: int = 3
    JOB_MAX_ATTEMPTS: int = 3
    JOB_BACKOFF: list[int] = dataclasses.field(default_factory=lambda: [10, 60, 300])
    JOB_LOCK_TIMEOUT_S: int = 300
    N_WORKER: int = 1
    INVENTORY_PATHS: list[str] = dataclasses.field(
        default_factory=lambda: ["conf/inventory.yaml", "conf/identities.yaml", "conf/iocs.csv"]
    )
    LLM_BASE_URL: str = ""
    LLM_API_KEY: str = ""
    LLM_MODEL_PROPOSER: str = ""
    LLM_MODEL_VERIFIER: str = ""
    LLM_TIMEOUT_S: int = 120
    LLM_RETRY: int = 2
    LLM_THINKING: str = "disabled"
    LLM_MONTHLY_USD_CAP: int = 30
    LLM_PRICE_IN_PER_M: float = 0.0
    LLM_PRICE_OUT_PER_M: float = 0.0
    PROMPT_TOTAL_BUDGET_TOKENS: int = 40_000
    CASE_PROMPT_BUDGET_TOKENS: int = 60_000
    ANALYZE_QUOTA_PER_USER_DAY: int = 30
    NEVER_AUTOCLOSE_AGENTS: list[str] = dataclasses.field(default_factory=list)
    AUTOCLOSE_RULE_WIDTH_PCT: int = 30
    REVIEW_DELTA_TOLERANCE: int = 20
    MAX_ALERTS_PER_CASE: int = 200
    JWT_SECRET: str = ""
    JWT_TTL_HOURS: int = 8
    LOGIN_MAX_FAILS: int = 5
    LOCKOUT_MINUTES: int = 15
    WEBHOOK_API_KEY: str = ""
    WEBHOOK_IP_ALLOWLIST: list[str] = dataclasses.field(default_factory=list)
    RETENTION_DAYS: int = 365
    BACKUP_HOUR: int = 2
    EVAL_BLIND_FRACTION: float = 0.5
    DISPLAY_TZ: str = "Asia/Ho_Chi_Minh"
    NOTIFY_TELEGRAM_BOT_TOKEN: str = ""
    NOTIFY_TELEGRAM_CHAT_ID: str = ""

    @property
    def llm_enabled(self) -> bool:
        return bool(self.LLM_MODEL_PROPOSER)

    def dump(self) -> dict[str, object]:
        """Every field, secrets redacted to `'***'` when non-empty."""
        result: dict[str, object] = {}
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            result[f.name] = "***" if f.name in _SECRET_FIELDS and value else value
        return result

    def __repr__(self) -> str:
        rendered = ", ".join(f"{name}={value!r}" for name, value in self.dump().items())
        return f"Config({rendered})"


def load(*, env_file: str | Path = ".env") -> Config:
    file_values = _read_env_file(Path(env_file))

    def raw(key: str) -> str | None:
        value = os.environ.get(key)
        if value:
            return value
        value = file_values.get(key)
        if value:
            return value
        return None

    def as_str(key: str, default: str) -> str:
        value = raw(key)
        return default if value is None else value

    def as_int(key: str, default: int) -> int:
        value = raw(key)
        return default if value is None else _parse_int(key, value)

    def as_float(key: str, default: float) -> float:
        value = raw(key)
        return default if value is None else _parse_float(key, value)

    def as_json_list(key: str, default: list, item_type: type) -> list:
        value = raw(key)
        return list(default) if value is None else _parse_json_list(key, value, item_type)

    def as_enum(key: str, default: str, allowed: tuple[str, ...]) -> str:
        value = raw(key)
        return default if value is None else _parse_enum(key, value, allowed)

    llm_model_proposer = as_str("LLM_MODEL_PROPOSER", "")
    verifier_raw = raw("LLM_MODEL_VERIFIER")
    llm_model_verifier = llm_model_proposer if verifier_raw is None else verifier_raw

    max_payload_bytes = as_int(_MAX_PAYLOAD_KEY, 2_097_152)
    raw_log_max_bytes = as_int(_RAW_LOG_KEY, 1_024_000)
    if max_payload_bytes <= raw_log_max_bytes:
        max_key, raw_key = _MAX_PAYLOAD_KEY, _RAW_LOG_KEY
        raise ConfigError(
            f"{max_key} ({max_payload_bytes}) must be greater than "
            f"{raw_key} ({raw_log_max_bytes})"
        )

    return Config(
        DATABASE_URL=as_str("DATABASE_URL", ""),
        DATABASE_URL_OWNER=as_str("DATABASE_URL_OWNER", "postgresql:///soc_dev"),
        TEST_DATABASE_URL=as_str("TEST_DATABASE_URL", "postgresql:///soc_test"),
        MAX_PAYLOAD_BYTES=max_payload_bytes,
        RAW_LOG_MAX_BYTES=raw_log_max_bytes,
        PROMPT_LOG_MAX_BYTES=as_int("PROMPT_LOG_MAX_BYTES", 32_768),
        DEDUP_IDLE_GAP_MINUTES=as_int("DEDUP_IDLE_GAP_MINUTES", 15),
        MAX_CLUSTER_AGE_HOURS=as_int("MAX_CLUSTER_AGE_HOURS", 4),
        MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES=as_int("MAX_CLUSTER_AGE_AUTOCLOSED_MINUTES", 30),
        MAX_CLUSTER_SIZE=as_int("MAX_CLUSTER_SIZE", 1000),
        INDEXER_URL=as_str("INDEXER_URL", ""),
        INDEXER_USER=as_str("INDEXER_USER", ""),
        INDEXER_PASSWORD=as_str("INDEXER_PASSWORD", ""),
        INDEXER_CA=as_str("INDEXER_CA", ""),
        INDEXER_INDEX=as_str("INDEXER_INDEX", "wazuh-alerts-*"),
        PULL_INTERVAL_S=as_int("PULL_INTERVAL_S", 60),
        PULL_OVERLAP_S=as_int("PULL_OVERLAP_S", 60),
        PULL_PAGE=as_int("PULL_PAGE", 500),
        PULL_START=as_str("PULL_START", "2026-08-01"),
        HEARTBEAT_RULE_ID=as_str("HEARTBEAT_RULE_ID", "100999"),
        HEARTBEAT_MAX_AGE_MIN=as_int("HEARTBEAT_MAX_AGE_MIN", 30),
        SILENCE_WARN_HOURS=as_int("SILENCE_WARN_HOURS", 3),
        JOB_MAX_ATTEMPTS=as_int("JOB_MAX_ATTEMPTS", 3),
        JOB_BACKOFF=as_json_list("JOB_BACKOFF", [10, 60, 300], int),
        JOB_LOCK_TIMEOUT_S=as_int("JOB_LOCK_TIMEOUT_S", 300),
        N_WORKER=as_int("N_WORKER", 1),
        INVENTORY_PATHS=as_json_list(
            "INVENTORY_PATHS",
            ["conf/inventory.yaml", "conf/identities.yaml", "conf/iocs.csv"],
            str,
        ),
        LLM_BASE_URL=as_str("LLM_BASE_URL", ""),
        LLM_API_KEY=as_str("LLM_API_KEY", ""),
        LLM_MODEL_PROPOSER=llm_model_proposer,
        LLM_MODEL_VERIFIER=llm_model_verifier,
        LLM_TIMEOUT_S=as_int("LLM_TIMEOUT_S", 120),
        LLM_RETRY=as_int("LLM_RETRY", 2),
        LLM_THINKING=as_enum("LLM_THINKING", "disabled", _LLM_THINKING_VALUES),
        LLM_MONTHLY_USD_CAP=as_int("LLM_MONTHLY_USD_CAP", 30),
        LLM_PRICE_IN_PER_M=as_float("LLM_PRICE_IN_PER_M", 0.0),
        LLM_PRICE_OUT_PER_M=as_float("LLM_PRICE_OUT_PER_M", 0.0),
        PROMPT_TOTAL_BUDGET_TOKENS=as_int("PROMPT_TOTAL_BUDGET_TOKENS", 40_000),
        CASE_PROMPT_BUDGET_TOKENS=as_int("CASE_PROMPT_BUDGET_TOKENS", 60_000),
        ANALYZE_QUOTA_PER_USER_DAY=as_int("ANALYZE_QUOTA_PER_USER_DAY", 30),
        NEVER_AUTOCLOSE_AGENTS=as_json_list("NEVER_AUTOCLOSE_AGENTS", [], str),
        AUTOCLOSE_RULE_WIDTH_PCT=as_int("AUTOCLOSE_RULE_WIDTH_PCT", 30),
        REVIEW_DELTA_TOLERANCE=as_int("REVIEW_DELTA_TOLERANCE", 20),
        MAX_ALERTS_PER_CASE=as_int("MAX_ALERTS_PER_CASE", 200),
        JWT_SECRET=as_str("JWT_SECRET", ""),
        JWT_TTL_HOURS=as_int("JWT_TTL_HOURS", 8),
        LOGIN_MAX_FAILS=as_int("LOGIN_MAX_FAILS", 5),
        LOCKOUT_MINUTES=as_int("LOCKOUT_MINUTES", 15),
        WEBHOOK_API_KEY=as_str("WEBHOOK_API_KEY", ""),
        WEBHOOK_IP_ALLOWLIST=as_json_list("WEBHOOK_IP_ALLOWLIST", [], str),
        RETENTION_DAYS=as_int("RETENTION_DAYS", 365),
        BACKUP_HOUR=as_int("BACKUP_HOUR", 2),
        EVAL_BLIND_FRACTION=as_float("EVAL_BLIND_FRACTION", 0.5),
        DISPLAY_TZ=as_str("DISPLAY_TZ", "Asia/Ho_Chi_Minh"),
        NOTIFY_TELEGRAM_BOT_TOKEN=as_str("NOTIFY_TELEGRAM_BOT_TOKEN", ""),
        NOTIFY_TELEGRAM_CHAT_ID=as_str("NOTIFY_TELEGRAM_CHAT_ID", ""),
    )
