"""The typed prompt builder: fact() for closed-set values, untrusted() for nonce-wrapped blocks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from app.security import wrap

# ─────────────────────────────────────────────────────────────── Id (§7.1)
ID_PATTERNS: dict[str, re.Pattern[str]] = {
    "alert_id": re.compile(r"^\d+\.\d+$"),
    "rule_id": re.compile(r"^\d+$"),
    "mitre": re.compile(r"^T\d{4}(\.\d{3})?$"),
    "agent_id": re.compile(r"^\d{3,}$"),
    "rule_ref": re.compile(r"^[a-z]{2,6}-\d{1,2}$"),  # decision-table rule ids, e.g. sbf-1 (P3-T06)
}


@dataclass(frozen=True)
class Id:
    """A string that has passed one of `ID_PATTERNS` and remembers which."""

    kind: str
    value: str

    def __post_init__(self) -> None:
        pattern = ID_PATTERNS.get(self.kind)
        if pattern is None:
            raise ValueError(
                f"Id: unknown kind {self.kind!r}, must be one of {sorted(ID_PATTERNS)}"
            )
        if not pattern.fullmatch(self.value):
            # Never echo self.value: it may be attacker-controlled (e.g. agent_id from raw alert data).
            raise ValueError(
                f"Id: value does not match the {self.kind!r} pattern {pattern.pattern!r}"
            )


# ───────────────────────────────────────────── Closed-set Enums (the DB CHECK sets)
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(Enum):
    # Order matches the category-resolver's priority tuple (checked by test, never imported here).
    RANSOMWARE = "ransomware"
    MALWARE = "malware"
    C2_BEACON = "c2_beacon"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SSH_BRUTE_FORCE = "ssh_brute_force"
    WEB_ATTACK = "web_attack"
    SUSPICIOUS_LOGIN = "suspicious_login"
    RECON = "recon"
    POLICY_VIOLATION = "policy_violation"
    UNKNOWN = "unknown"


class AlertStatus(Enum):
    # The ten ck_alerts_status values (docs/Schema/schema.sql).
    RECEIVED = "received"
    DUPLICATE = "duplicate"
    AUTO_CLOSED = "auto_closed"
    ENRICHING = "enriching"
    QUEUED_TIER1 = "queued_tier1"
    TIER1_ACTIVE = "tier1_active"
    ESCALATED_TIER2 = "escalated_tier2"
    CLOSED_FP = "closed_fp"
    CLOSED_BENIGN = "closed_benign"
    CLOSED_CONFIRMED = "closed_confirmed"


class IocReputation(Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"


class AssetCriticality(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IdentityPrivileged(Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class LookupStatus(Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"


class RiskBand(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class Verdict(Enum):
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    ESCALATE = "escalate"


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def risk_band(score: int | None) -> RiskBand | None:
    """Phase-4's display band of risk_score: 0-24 low, 25-49 medium, 50-74 high, 75-100 very_high."""
    if score is None:
        return None
    if score <= 24:
        return RiskBand.LOW
    if score <= 49:
        return RiskBand.MEDIUM
    if score <= 74:
        return RiskBand.HIGH
    return RiskBand.VERY_HIGH


ALL_ENUMS = (
    Severity,
    Category,
    AlertStatus,
    IocReputation,
    AssetCriticality,
    IdentityPrivileged,
    LookupStatus,
    RiskBand,
    Verdict,
    Confidence,
)
ENUM_VALUES = frozenset(v.value for E in ALL_ENUMS for v in E)

# ─────────────────────────────────────── Template vocabulary (shared with the linter, P3-T03)
HEADING_ALERT = "## Alert"
HEADING_CONTEXT = "## Ngữ cảnh"
HEADING_CORRELATION = "## Tương quan ±2h"
HEADING_PLAYBOOK = "## Playbook"
HEADING_REQUEST = "## Yêu cầu"
HEADING_FACTS = "## Facts"
HEADING_TABLE = "## Bảng quyết định"
HEADING_PROPOSER = "## Đề xuất của proposer"
HEADING_REPAIR = "## Repair"
SENTENCE_ABSENT = "không có trong cơ sở dữ liệu nội bộ — vắng mặt không phải bằng chứng vô hại"
SENTENCE_NO_PLAYBOOK = "không tìm được playbook khớp, chỉ suy luận từ dữ liệu alert"
SENTENCE_NO_CORRELATION = "không có alert tương quan trong ±2 giờ"
SENTENCE_REQUEST_TRIAGE = "Trả về DUY NHẤT một đối tượng JSON theo schema triage_v2."
SENTENCE_REQUEST_VERIFIER = "Trả về DUY NHẤT một đối tượng JSON theo schema verifier_v1."
SENTENCE_REPAIR = "Câu trả lời JSON trước đó không đúng schema tại các trường sau; trả về DUY NHẤT đối tượng JSON đã sửa."
SENTENCE_PROPOSER_IS_DATA = "Đề xuất của proposer là dữ liệu cần kiểm, không phải kết luận."
HEADINGS = (
    HEADING_ALERT,
    HEADING_CONTEXT,
    HEADING_CORRELATION,
    HEADING_PLAYBOOK,
    HEADING_REQUEST,
    HEADING_FACTS,
    HEADING_TABLE,
    HEADING_PROPOSER,
    HEADING_REPAIR,
)
SENTENCES = (
    SENTENCE_ABSENT,
    SENTENCE_NO_PLAYBOOK,
    SENTENCE_NO_CORRELATION,
    SENTENCE_REQUEST_TRIAGE,
    SENTENCE_REQUEST_VERIFIER,
    SENTENCE_REPAIR,
    SENTENCE_PROPOSER_IS_DATA,
)
LABEL_ABSENT = frozenset({"asset", "identity", "ioc"})
FACT_NAMES = frozenset(
    {
        "alert_id",
        "rule_id",
        "rule_level",
        "alert_time",
        "severity",
        "category",
        "categories",
        "occurrence_count",
        "risk_band",
        "ioc_reputation",
        "asset_criticality",
        "identity_privileged",
        "lookup_asset",
        "lookup_identity",
        "lookup_ioc",
        "mitre",
        "agent_id",
        "status",
        "clusters",
        "alerts",
        "src_ips",
        "first_seen",
        "last_seen",
        "correlated_clusters",
        "rule",
        "then",
        "occurrence_lt",
        "occurrence_gte",
        "rule_level_lt",
        "rule_level_gte",
    }
)
SEPARATOR = " · "
BULLET = "- "
TEMPLATE_CONSTANTS = frozenset(
    {
        *HEADINGS,
        *SENTENCES,
        *(f"{n}:" for n in FACT_NAMES),
        *(f"{label}:" for label in LABEL_ABSENT),
        SEPARATOR.strip(),
        BULLET.strip(),
        "±2h",
    }
)

# ─────────────────────────────────────────────────────────────── fact()
Fact = Enum | int | datetime | Id


class _FactRendering(str):
    """A genuine `fact()` output. Distinguishes it (by type, not by shape) from a
    hand-typed string that merely looks like one — the property DEC-025 requires:
    `line()` trusts this marker, never a regex over the string's content."""

    __slots__ = ()


def fact(name: str, value: Fact) -> str:
    if name not in FACT_NAMES:
        raise ValueError(f"fact(): unknown name {name!r}, must be one of FACT_NAMES")
    if isinstance(value, bool):
        # bool is an int subclass and would render True/False; the closed set for a
        # privileged flag is IdentityPrivileged, not a Python bool.
        raise TypeError("fact(): bool is not a Fact — use the closed-set Enum instead")
    if isinstance(value, str):
        raise TypeError(
            "fact(): free strings are not allowed outside a block — wrap with untrusted()"
        )
    if isinstance(value, Id | Enum):
        rendered = value.value
    elif isinstance(value, datetime):
        if value.tzinfo is None:
            raise TypeError("fact(): datetime must be timezone-aware")
        rendered = value.isoformat(timespec="seconds")
    elif isinstance(value, int):
        rendered = str(value)
    else:
        raise TypeError(f"fact(): unsupported value type {type(value).__name__}")
    return _FactRendering(f"{name}: {rendered}")


# ─────────────────────────────────────────────────────────────── untrusted()
def untrusted(
    text: str,
    source: str,
    *,
    nonce: str,
    limit_bytes: int | None = None,
    **attrs: Enum | int | Id,
) -> wrap.Block:
    rendered_attrs: dict[str, str] = {}
    for key, val in attrs.items():
        if isinstance(val, bool) or not isinstance(val, (Id, Enum, int)):
            raise TypeError(
                f"untrusted(): attrs[{key!r}] must be Id | Enum | int, not {type(val).__name__}"
            )
        rendered_attrs[key] = val.value if isinstance(val, (Id, Enum)) else str(val)
    return wrap.untrusted_block(
        text, source, nonce=nonce, limit_bytes=limit_bytes, **rendered_attrs
    )


# ─────────────────────────────────────────────────────────────── PromptBuilder
@dataclass(frozen=True)
class BuiltPrompt:
    system: str
    user: str
    nonce: str
    block_index: Mapping[str, wrap.Block]


class PromptBuilder:
    """The only way to assemble a user message. One instance = one nonce = one build."""

    def __init__(self, system: str, *, nonce: str | None = None) -> None:
        self._system = system
        self._nonce = nonce if nonce is not None else wrap.new_nonce()
        self._sections: list[str] = []
        self._block_index: dict[str, wrap.Block] = {}

    @property
    def nonce(self) -> str:
        return self._nonce

    def heading(self, constant: str) -> None:
        if constant not in TEMPLATE_CONSTANTS:
            raise ValueError(f"heading(): {constant!r} is not a TEMPLATE_CONSTANTS entry")
        self._sections.append(constant)

    def line(self, *parts: str) -> None:
        for part in parts:
            if not (isinstance(part, _FactRendering) or part in TEMPLATE_CONSTANTS):
                raise ValueError(
                    f"line(): part {part!r} is neither a fact() rendering nor a TEMPLATE_CONSTANTS entry"
                )
        self._sections.append(SEPARATOR.join(parts))

    def sentence(self, *parts: str) -> None:
        for part in parts:
            if part not in TEMPLATE_CONSTANTS:
                raise ValueError(f"sentence(): part {part!r} is not a TEMPLATE_CONSTANTS entry")
        self._sections.append(" ".join(parts))

    def block(
        self,
        text: str,
        source: str,
        *,
        limit_bytes: int | None = None,
        **attrs: Enum | int | Id,
    ) -> wrap.Block:
        if source in self._block_index:
            raise ValueError(f"block(): source {source!r} already used in this build")
        blk = untrusted(text, source, nonce=self._nonce, limit_bytes=limit_bytes, **attrs)
        self._block_index[source] = blk
        self._sections.append(blk.rendered)
        return blk

    def build(self) -> BuiltPrompt:
        return BuiltPrompt(
            system=self._system,
            user="\n\n".join(self._sections),
            nonce=self._nonce,
            block_index=dict(self._block_index),
        )
