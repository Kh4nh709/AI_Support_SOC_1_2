"""Pipeline ①: the proposer prompt from the five blocks, the facts-only verifier prompt,
`propose()` / `verify()` with one repair round, and `prompt_version` (P3-T09).

This module knows what an alert looks like as a prompt and nothing else. Every free-text
value (description, raw_log, hostnames, usernames, owner/role text, correlation samples,
playbook prose, the proposer's answer) goes through `PromptBuilder.block()`; every
out-of-block value is a `fact()` over a closed-set Enum, an int, a datetime or a
regex-checked `Id` — there is no other API, so a free string cannot reach the outside of
a block (context pack §7.1, architecture §4.1). The token budget is estimated before a
call and cut in phase-5's order (raw_log → samples → correlation rows; never the alert,
never the playbook) with one warning per cut that changed something; the list becomes
`llm_runs.citation_warnings` (P3-T10).

Inputs are plain values, not a connection: `TriageInput` is filled by P3-T10 from the
`alerts` row with an explicit column list, and the correlation summary is taken
*structurally* — `llm` may import only `security`, `infra` and `kb` (context pack §4),
never `domain`, so `CorrelationRowLike` / `CorrelationLike` below are `typing.Protocol`s
over the eight row attributes (`rule_id, category, status, cluster_count, alert_count,
first_seen, last_seen, src_ip_count`) and the `samples` sequence of dicts that
`app.domain.correlation.CorrelationRow` / `CorrelationSummary` carry. P3-T10 passes the
real objects; the tests build them from `app.domain.correlation` directly.

The repair round (planning decision 9) is a fresh single-turn call: the same system
prompt, the original user message plus `HEADING_REPAIR`, `SENTENCE_REPAIR` and one bullet
per validation error. The validator's messages carry field paths and vocabularies, never
values — except the *path* of an `unexpected key`, which is the model's own key; the
sanitiser here rewrites that to the parent object's path and normalises array indices to
the schema's `[]` form, so every bullet is composed of `REPAIR_CONSTANTS` (the two
schemas' field paths and the validator's message vocabulary). The assembled repair
message is linted before it is sent; a residual violation is a template defect and raises
`RepairPromptViolation` (a `PermanentError`) instead of making the call.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from app.infra.config import Config
from app.infra.errors import PermanentError
from app.kb.lookup import DecisionTable
from app.llm import schemas
from app.llm.adapter import estimate_tokens
from app.llm.builder import (
    BULLET,
    ENUM_VALUES,
    HEADING_ALERT,
    HEADING_CONTEXT,
    HEADING_CORRELATION,
    HEADING_FACTS,
    HEADING_PLAYBOOK,
    HEADING_PROPOSER,
    HEADING_REPAIR,
    HEADING_REQUEST,
    HEADING_TABLE,
    SENTENCE_ABSENT,
    SENTENCE_NO_CORRELATION,
    SENTENCE_NO_PLAYBOOK,
    SENTENCE_PROPOSER_IS_DATA,
    SENTENCE_REPAIR,
    SENTENCE_REQUEST_TRIAGE,
    SENTENCE_REQUEST_VERIFIER,
    TEMPLATE_CONSTANTS,
    AlertStatus,
    AssetCriticality,
    BuiltPrompt,
    Category,
    Id,
    IdentityPrivileged,
    IocReputation,
    LookupStatus,
    PromptBuilder,
    Severity,
    Verdict,
    fact,
    risk_band,
)
from app.security import linter, wrap

TRIAGE_TEMPLATE = Path(__file__).resolve().parent / "templates" / "triage_system.txt"
VERIFIER_TEMPLATE = Path(__file__).resolve().parent / "templates" / "verifier_system.txt"

#: Phase-5's caps: ≤ 20 grouped correlation rows, ≤ 5 representative alerts, each
#: sample's raw_log cut to 2 KB with the marker inside the block (design note 2).
MAX_CORRELATION_ROWS = 20
MAX_CORRELATION_SAMPLES = 5
SAMPLE_RAW_LOG_LIMIT_BYTES = 2_048
#: The budget cut targets (design note 3): raw_log 32 KB → 8 KB, samples 5 → 3 → 0,
#: rows 20 → 10; then send anyway with `budget_exceeded_after_cuts`.
RAW_LOG_CUT_BYTES = 8_192
SAMPLES_CUT = 3
ROWS_CUT = 10

_LOOKUP_LABELS = ("asset", "identity", "ioc")
_LIST_CONDITION_ENUMS: dict[str, type[Enum]] = {
    "severity": Severity,
    "ioc_reputation": IocReputation,
    "asset_criticality": AssetCriticality,
    "identity_privileged": IdentityPrivileged,
}


# ─────────────────────────────────────────────────────────── inputs (design note 1)
class CorrelationRowLike(Protocol):
    """Structural twin of `app.domain.correlation.CorrelationRow` — closed-set, numeric
    or datetime only (G6′), placed outside a block as facts."""

    @property
    def rule_id(self) -> str: ...
    @property
    def category(self) -> str: ...
    @property
    def status(self) -> str: ...
    @property
    def cluster_count(self) -> int: ...
    @property
    def alert_count(self) -> int: ...
    @property
    def first_seen(self) -> datetime: ...
    @property
    def last_seen(self) -> datetime: ...
    @property
    def src_ip_count(self) -> int: ...


class CorrelationLike(Protocol):
    """Structural twin of `app.domain.correlation.CorrelationSummary`: `rows` (≤ 20) and
    `samples` (≤ 5 dicts with an explicit column list — the only free text)."""

    @property
    def rows(self) -> Sequence[CorrelationRowLike]: ...
    @property
    def samples(self) -> Sequence[Mapping[str, Any]]: ...


@dataclass(frozen=True)
class TriageInput:
    """One `alerts` row as plain values (P3-T10 fills this with an explicit column list,
    G10) — the four jsonb context columns as dicts."""

    alert_id: str
    rule_id: str
    rule_level: int
    alert_time: datetime
    severity: str
    category: str
    categories: tuple[str, ...]
    occurrence_count: int
    risk_score: int | None
    description: str
    raw_log: str
    raw_log_truncated: bool
    agent_name: str
    origin_host: str
    agent_id: str | None
    alert_user: str | None
    mitre_ids: tuple[str, ...]
    asset_context: Mapping[str, Any]
    identity_context: Mapping[str, Any]
    ioc_context: Mapping[str, Any]
    lookup_status: Mapping[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime


@dataclass(frozen=True)
class BuiltTriagePrompt:
    prompt: BuiltPrompt
    warnings: list[str]
    estimated_tokens: int
    playbook_used_effective: str | None


@dataclass(frozen=True)
class Proposal:
    content: str  # the last call's `choices[0].message.content`, verbatim
    parsed: dict | None  # the schema-valid object, or None after the repair round failed
    schema_errors: list[str]  # the last call's validation errors ([] when `parsed` is set)
    repaired: bool
    usage: dict  # summed over the calls made
    model: str  # from the last call
    latency_ms: int  # summed over the calls made
    calls: int  # 1 or 2 — never 3 (design note 5)


Verification = Proposal  # same shape, schema "verifier_v1"


class RepairPromptViolation(PermanentError):
    """The assembled repair prompt failed the linter — a template defect, not a model
    outcome; the call is not made."""


# ─────────────────────────────────────────────────────────── facts (planning decision 7)
def _asset_criticality(asset_context: Mapping[str, Any]) -> str:
    value = asset_context.get("criticality")
    return AssetCriticality.UNKNOWN.value if value is None else AssetCriticality(value).value


def _ioc_reputation(ioc_context: Mapping[str, Any]) -> str:
    value = ioc_context.get("reputation")
    return IocReputation.SKIPPED.value if value is None else IocReputation(value).value


def _identity_privileged(identity_context: Mapping[str, Any]) -> str:
    """`identity_context.privileged` `true|false|null` → `"true"|"false"|"unknown"`."""
    value = identity_context.get("privileged")
    if isinstance(value, bool):
        return IdentityPrivileged.TRUE.value if value else IdentityPrivileged.FALSE.value
    if value is None:
        return IdentityPrivileged.UNKNOWN.value
    return IdentityPrivileged(value).value


def build_facts(inp: TriageInput, correlation: CorrelationLike | None) -> dict[str, Any]:
    """The dict gate step 2, step 4, the verifier prompt and B1 all read (planning
    decision 7) — exactly these keys; every value closed-set, int or ISO datetime, so
    it is JSON-serialisable into `gate_result.facts`."""
    by_category: dict[str, int] = {}
    if correlation is not None:
        for row in correlation.rows:
            by_category[row.category] = by_category.get(row.category, 0) + int(row.cluster_count)
    return {
        "severity": Severity(inp.severity).value,
        "category": Category(inp.category).value,
        "rule_level": int(inp.rule_level),
        "occurrence_count": int(inp.occurrence_count),
        "ioc_reputation": _ioc_reputation(inp.ioc_context),
        "asset_criticality": _asset_criticality(inp.asset_context),
        "identity_privileged": _identity_privileged(inp.identity_context),
        "correlated_clusters": sum(by_category.values()),
        "correlated_by_category": by_category,
        "first_seen_at": inp.first_seen_at.isoformat(),
        "last_seen_at": inp.last_seen_at.isoformat(),
    }


# ─────────────────────────────────────────────────────────── the system prompts
def _system_prompt(template: Path, schema_name: str) -> str:
    """Planning decision 14: the template file plus the rendered schema."""
    text = template.read_text("utf-8")
    return f"{text}\n\n## Schema {schema_name}\n{schemas.render(schema_name)}"


def _estimate(prompt: BuiltPrompt) -> int:
    return estimate_tokens(prompt.system) + estimate_tokens(prompt.user)


# ─────────────────────────────────────────────────────────── the ① prompt (design note 2)
def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    return str(value)


def _render_sample(sample: Mapping[str, Any]) -> str:
    """One representative alert: the header line from the explicit column list, then
    `description`, then `raw_log` cut to 2 KB with the marker inside (phase-5:104)."""
    raw_log, _ = wrap.truncate_block(str(sample.get("raw_log") or ""), SAMPLE_RAW_LOG_LIMIT_BYTES)
    header = (
        f"alert_id={sample.get('alert_id')} rule_id={sample.get('rule_id')} "
        f"severity={sample.get('severity')} status={sample.get('status')} "
        f"occurrence={sample.get('occurrence_count')} alert_time={_iso(sample.get('alert_time'))}"
    )
    return "\n".join((header, str(sample.get("description") or ""), raw_log))


def _lookup(inp: TriageInput, label: str) -> str:
    value = inp.lookup_status.get(label)
    return LookupStatus.SKIPPED.value if value is None else LookupStatus(value).value


def _alert_section(
    pb: PromptBuilder, inp: TriageInput, facts: Mapping[str, Any], warnings: list[str]
) -> Id:
    alert_id = Id("alert_id", inp.alert_id)
    pb.heading(HEADING_ALERT)
    pb.line(
        fact("alert_id", alert_id),
        fact("rule_id", Id("rule_id", inp.rule_id)),
        fact("rule_level", int(inp.rule_level)),
        fact("alert_time", inp.alert_time),
    )
    parts = [
        fact("severity", Severity(inp.severity)),
        fact("category", Category(inp.category)),
        fact("occurrence_count", int(inp.occurrence_count)),
    ]
    band = risk_band(inp.risk_score)
    if band is not None:
        parts.append(fact("risk_band", band))
    pb.line(*parts)
    pb.line(
        fact("ioc_reputation", IocReputation(facts["ioc_reputation"])),
        fact("asset_criticality", AssetCriticality(facts["asset_criticality"])),
        fact("identity_privileged", IdentityPrivileged(facts["identity_privileged"])),
    )
    pb.line(
        *(fact(f"lookup_{label}", LookupStatus(_lookup(inp, label))) for label in _LOOKUP_LABELS)
    )
    if len(inp.categories) > 1:
        pb.line(*(fact("categories", Category(c)) for c in inp.categories))
    mitre: list[str] = []
    for raw in inp.mitre_ids:
        try:
            mitre.append(fact("mitre", Id("mitre", raw)))
        except ValueError:
            warnings.append("invalid_mitre_id")  # never the value: it is alert data
    if mitre:
        pb.line(*mitre)
    if inp.agent_id is not None:
        try:
            pb.line(fact("agent_id", Id("agent_id", inp.agent_id)))
        except ValueError:
            warnings.append("invalid_agent_id")
    return alert_id


def _context_section(pb: PromptBuilder, inp: TriageInput) -> None:
    pb.heading(HEADING_CONTEXT)
    status = {label: _lookup(inp, label) for label in _LOOKUP_LABELS}
    for label in _LOOKUP_LABELS:  # the legacy sentence 1, its placement rule kept: outside
        if status[label] == LookupStatus.NOT_FOUND.value:
            pb.sentence(f"{label}:", SENTENCE_ABSENT)
    lines: list[str] = []
    if status["asset"] == LookupStatus.FOUND.value:
        owner = inp.asset_context.get("owner") or ""
        role = inp.asset_context.get("role") or ""
        lines.append(
            f"asset: hostname={inp.agent_name} origin_host={inp.origin_host} "
            f"owner={owner} role={role}"
        )
    if status["identity"] == LookupStatus.FOUND.value:
        lines.append(f"identity: username={inp.alert_user or ''}")
    if status["ioc"] == LookupStatus.FOUND.value:
        lines.append(f"ioc: {_ioc_reputation(inp.ioc_context)}")
    if lines:  # hostnames, owner, role, username are free text and live here and nowhere else
        pb.block("\n".join(lines), "context")


def _correlation_section(
    pb: PromptBuilder, rows: Sequence[CorrelationRowLike], samples: Sequence[Mapping[str, Any]]
) -> None:
    pb.heading(HEADING_CORRELATION)
    if not rows:
        pb.sentence(SENTENCE_NO_CORRELATION)
        return
    for row in rows:
        pb.line(
            fact("rule_id", Id("rule_id", row.rule_id)),
            fact("category", Category(row.category)),
            fact("status", AlertStatus(row.status)),
            fact("clusters", int(row.cluster_count)),
            fact("alerts", int(row.alert_count)),
            fact("src_ips", int(row.src_ip_count)),
            fact("first_seen", row.first_seen),
            fact("last_seen", row.last_seen),
        )
    if samples:
        pb.block("\n\n".join(_render_sample(s) for s in samples), "correlation_samples")


def _playbook_section(
    pb: PromptBuilder,
    inp: TriageInput,
    playbook_text: str | None,
    table: DecisionTable | None,
    warnings: list[str],
) -> str | None:
    """The prose block is sent whenever it exists; `playbook_used_effective` is set only
    when the machine table is reviewed too (architecture §3.10)."""
    pb.heading(HEADING_PLAYBOOK)
    if not playbook_text:
        pb.sentence(SENTENCE_NO_PLAYBOOK)  # the legacy sentence 2: `unknown` or a missing file
        warnings.append("no_playbook")
        return None
    pb.block(playbook_text, "kb_playbook", category=Category(inp.category))
    if table is None:
        warnings.append(f"no_table:{inp.category}")
        return None
    if not table.reviewed:
        warnings.append(f"decision_table_unreviewed:{inp.category}")
        return None
    return inp.category


def _render_proposer(
    inp: TriageInput,
    facts: Mapping[str, Any],
    rows: Sequence[CorrelationRowLike],
    samples: Sequence[Mapping[str, Any]],
    playbook_text: str | None,
    table: DecisionTable | None,
    *,
    system: str,
    nonce: str,
    raw_log_limit: int,
    include_context: bool,
    include_correlation: bool,
) -> tuple[BuiltPrompt, list[str], str | None]:
    warnings: list[str] = []
    pb = PromptBuilder(system, nonce=nonce)
    alert_id = _alert_section(pb, inp, facts, warnings)
    pb.block(inp.description, "rule_description", alert_id=alert_id)
    pb.block(inp.raw_log, "wazuh_raw_log", limit_bytes=raw_log_limit, alert_id=alert_id)
    if inp.raw_log_truncated:
        warnings.append("raw_log_truncated_at_ingest")
    if include_context:
        _context_section(pb, inp)
    if include_correlation:
        _correlation_section(pb, rows, samples)
    effective = _playbook_section(pb, inp, playbook_text, table, warnings)
    pb.heading(HEADING_REQUEST)
    pb.sentence(SENTENCE_REQUEST_TRIAGE)
    return pb.build(), warnings, effective


def build_proposer_prompt(
    inp: TriageInput,
    facts: Mapping[str, Any],
    correlation: CorrelationLike | None,
    playbook_text: str | None,
    table: DecisionTable | None,
    *,
    cfg: Config,
    include_context: bool = True,
    include_correlation: bool = True,
    nonce: str | None = None,
) -> BuiltTriagePrompt:
    """The ① user message, section by section (architecture §4.1), through
    `PromptBuilder` only; then the budget check and phase-5's cut order (design note 3).
    `include_context` / `include_correlation` are P7's B2 switches: the section — its
    heading, sentences and block — is omitted entirely."""
    system = _system_prompt(TRIAGE_TEMPLATE, "triage_v2")
    nonce = nonce if nonce is not None else wrap.new_nonce()
    rows: Sequence[CorrelationRowLike] = ()
    samples: Sequence[Mapping[str, Any]] = ()
    if include_correlation and correlation is not None:
        rows = tuple(correlation.rows)[:MAX_CORRELATION_ROWS]
        if rows:
            samples = tuple(correlation.samples)[:MAX_CORRELATION_SAMPLES]

    limits = {"raw_log": cfg.PROMPT_LOG_MAX_BYTES, "samples": len(samples), "rows": len(rows)}

    def render() -> tuple[BuiltPrompt, list[str], str | None]:
        return _render_proposer(
            inp,
            facts,
            rows[: limits["rows"]],
            samples[: limits["samples"]],
            playbook_text,
            table,
            system=system,
            nonce=nonce,
            raw_log_limit=limits["raw_log"],
            include_context=include_context,
            include_correlation=include_correlation,
        )

    prompt, warnings, effective = render()
    estimated = _estimate(prompt)
    budget = cfg.PROMPT_TOTAL_BUDGET_TOKENS
    cut_warnings: list[str] = []
    if estimated > budget:
        raw_log_bytes = len(inp.raw_log.encode("utf-8"))
        # (name, limit key, new value, whether the step changes anything) — a no-op is not a cut
        steps = (
            (
                "raw_log_cut_to_8192",
                "raw_log",
                RAW_LOG_CUT_BYTES,
                limits["raw_log"] > RAW_LOG_CUT_BYTES and raw_log_bytes > RAW_LOG_CUT_BYTES,
            ),
            ("correlation_samples_cut_to_3", "samples", SAMPLES_CUT, len(samples) > SAMPLES_CUT),
            ("correlation_samples_dropped", "samples", 0, len(samples) > 0),
            ("correlation_rows_cut_to_10", "rows", ROWS_CUT, len(rows) > ROWS_CUT),
        )
        for name, key, value, changes in steps:
            if not changes:
                continue
            limits[key] = value
            cut_warnings.append(name)
            prompt, warnings, effective = render()
            estimated = _estimate(prompt)
            if estimated <= budget:
                break
        else:
            cut_warnings.append("budget_exceeded_after_cuts")  # phase-5: "vẫn gửi"
    return BuiltTriagePrompt(
        prompt=prompt,
        warnings=warnings + cut_warnings,
        estimated_tokens=estimated,
        playbook_used_effective=effective,
    )


# ─────────────────────────────────────────────────────────── the verifier prompt (design note 4)
def _as_datetime(value: Any) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value))


def _table_section(
    pb: PromptBuilder, table: DecisionTable | None, category: str, warnings: list[str]
) -> str | None:
    """One line per rule, entirely from `fact()` calls: a list condition is one fact per
    enum value (`severity: low · severity: medium` — `line()` joins parts with the
    separator, there is no comma form through the typed API); a numeric condition is its
    own fact name (`occurrence_lt: 50`). A rule whose id fails the builder's `rule_ref`
    pattern is omitted with a warning — `kb/lookup.py` admits ids the pattern does not."""
    pb.heading(HEADING_TABLE)
    if table is None:
        pb.sentence(SENTENCE_NO_PLAYBOOK)
        unknown = category == Category.UNKNOWN.value
        warnings.append("no_playbook" if unknown else f"no_table:{category}")
        return None
    if not table.reviewed:
        pb.sentence(SENTENCE_NO_PLAYBOOK)
        warnings.append(f"decision_table_unreviewed:{category}")
        return None
    for rule in table.rules:
        try:
            rule_ref = Id("rule_ref", rule.id)
        except ValueError:
            warnings.append("invalid_rule_ref")
            continue
        parts = [fact("rule", rule_ref), fact("then", Verdict(rule.action))]
        for key, value in rule.condition.items():
            enum = _LIST_CONDITION_ENUMS.get(key)
            if enum is not None:
                parts.extend(fact(key, enum(v)) for v in value)
            else:
                parts.append(fact(key, int(value)))
        pb.line(*parts)
    return category


def build_verifier_prompt(
    facts: Mapping[str, Any],
    table: DecisionTable | None,
    verdict: str,
    reasons: list[dict],
    *,
    cfg: Config,
    nonce: str | None = None,
) -> BuiltTriagePrompt:
    """Architecture §4.3: facts and the reviewed decision table outside, the proposer's
    `{verdict, reasons}` inside the one `proposer` block. No hostnames, no usernames, no
    text — nothing of `TriageInput` is even passed in."""
    del cfg  # taken for symmetry with `build_proposer_prompt`; the verifier has no budget cuts
    system = _system_prompt(VERIFIER_TEMPLATE, "verifier_v1")
    warnings: list[str] = []
    pb = PromptBuilder(system, nonce=nonce)
    pb.heading(HEADING_FACTS)
    pb.line(
        fact("severity", Severity(facts["severity"])),
        fact("category", Category(facts["category"])),
        fact("rule_level", int(facts["rule_level"])),
        fact("occurrence_count", int(facts["occurrence_count"])),
        fact("ioc_reputation", IocReputation(facts["ioc_reputation"])),
        fact("asset_criticality", AssetCriticality(facts["asset_criticality"])),
        fact("identity_privileged", IdentityPrivileged(facts["identity_privileged"])),
    )
    pb.line(fact("correlated_clusters", int(facts["correlated_clusters"])))
    for category, clusters in dict(facts["correlated_by_category"]).items():
        pb.line(fact("category", Category(category)), fact("clusters", int(clusters)))
    pb.line(
        fact("first_seen", _as_datetime(facts["first_seen_at"])),
        fact("last_seen", _as_datetime(facts["last_seen_at"])),
    )
    effective = _table_section(pb, table, str(facts["category"]), warnings)
    pb.heading(HEADING_PROPOSER)
    pb.sentence(SENTENCE_PROPOSER_IS_DATA)
    pb.block(json.dumps({"verdict": verdict, "reasons": reasons}, ensure_ascii=False), "proposer")
    pb.heading(HEADING_REQUEST)
    pb.sentence(SENTENCE_REQUEST_VERIFIER)
    prompt = pb.build()
    return BuiltTriagePrompt(
        prompt=prompt,
        warnings=warnings,
        estimated_tokens=_estimate(prompt),
        playbook_used_effective=effective,
    )


# ─────────────────────────────────────────────────────────── the repair round (design note 5)
_ROOT = "<root>"
_ROOT_ERROR = f"{_ROOT}: expected a JSON object"
_ARRAY_INDEX_RE = re.compile(r"\[\d+\]")
_ENUM_TOKEN_RE = re.compile(r"^[a-z_]+$")
#: `llm/schemas.py`'s value-free message vocabulary (its module docstring), plus this
#: module's own root message. `expected one of <vocab>` is generated per enum leaf.
_MESSAGE_CONSTANTS = frozenset(
    {
        "missing",
        "unexpected key",
        "expected object",
        "expected array",
        "expected non-empty array",
        "expected boolean",
        "expected integer",
        "expected string",
        "expected string or null",
        "expected a JSON object",
    }
)


def _schema_paths(node: Any, prefix: str, paths: dict[str, str], vocabularies: set[str]) -> None:
    """Every dotted path of a §6.2 schema node → its kind (`object` | `array` | `leaf`),
    arrays in the rendered `[]` form; every enum leaf's `expected one of …` message."""
    if isinstance(node, dict):
        if prefix:
            paths[prefix] = "object"
        for key, sub in node.items():
            _schema_paths(sub, f"{prefix}.{key}" if prefix else key, paths, vocabularies)
    elif isinstance(node, list):
        paths[prefix] = "array"
        _schema_paths(node[0], f"{prefix}[]", paths, vocabularies)
    else:
        paths[prefix] = "leaf"
        if isinstance(node, str):
            alternatives = node.split("|")
            values = tuple(a for a in alternatives if a != "null")
            if "string" not in alternatives and all(_ENUM_TOKEN_RE.fullmatch(a) for a in values):
                vocabularies.add(f"expected one of {'|'.join(values)}")


def _repair_vocabulary(*names: str) -> tuple[dict[str, str], frozenset[str]]:
    paths: dict[str, str] = {}
    vocabularies: set[str] = set()
    for name in names:
        _schema_paths(schemas.load()[name], "", paths, vocabularies)
    constants = {f"{path}:" for path in paths} | {f"{_ROOT}:"} | _MESSAGE_CONSTANTS | vocabularies
    return paths, frozenset(constants)


_SCHEMA_PATHS, REPAIR_CONSTANTS = _repair_vocabulary("triage_v2", "verifier_v1")


def _object_prefix(path: str) -> str:
    """The longest known *object* prefix of `path` — the parent of an unexpected key,
    whatever the key itself contains (it is the model's, so it may carry dots)."""
    while path and _SCHEMA_PATHS.get(path) != "object":
        path = path.rsplit(".", 1)[0] if "." in path else ""
    return path


def _repair_line(error: str) -> str:
    """One validator message → one value-free bullet: array indices normalised to the
    schema's `[]` form; an `unexpected key` reported against its parent object, never
    the key (planning decision 9)."""
    path, _, message = error.partition(": ")
    path = _ARRAY_INDEX_RE.sub("[]", path)
    if message == "unexpected key":
        path = _object_prefix(path)
    return f"{BULLET}{path or _ROOT}: {message}"


def _repair_user(user: str, errors: list[str], *, nonce: str) -> str:
    suffix = "\n".join((HEADING_REPAIR, SENTENCE_REPAIR, *(_repair_line(e) for e in errors)))
    repair_user = f"{user}\n\n{suffix}"
    violations = linter.lint(
        repair_user,
        nonce=nonce,
        constants=TEMPLATE_CONSTANTS | REPAIR_CONSTANTS,
        enums=ENUM_VALUES,
    )
    if violations:
        first = violations[0]
        raise RepairPromptViolation(
            f"repair prompt failed the linter: {first.kind} at line {first.line} "
            f"({len(violations)} violation(s))"
        )
    return repair_user


def _parse(schema_name: str, content: str) -> tuple[dict | None, list[str]]:
    try:
        parsed = json.loads(content)
    except ValueError:  # json.JSONDecodeError
        return None, [_ROOT_ERROR]
    if not isinstance(parsed, dict):
        return None, [_ROOT_ERROR]
    return parsed, schemas.validate(schema_name, parsed)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _sum_usage(usages: Sequence[Mapping[str, Any]]) -> dict:
    """Key-wise sum of the numeric counters over the calls made; a non-numeric value
    (the adapter's `None` cache counters) is carried through, never added."""
    total: dict[str, Any] = {}
    for usage in usages:
        for key, value in usage.items():
            current = total.get(key)
            if _is_number(value) and _is_number(current):
                total[key] = current + value
            elif _is_number(value) or key not in total:
                total[key] = value
    return total


def _call(adapter: Any, built: BuiltTriagePrompt, *, schema_name: str, model: str) -> Proposal:
    """One call, validate, at most one repair, never a third call."""
    system, user = built.prompt.system, built.prompt.user
    result = adapter.complete(system=system, user=user, model=model)
    parsed, errors = _parse(schema_name, result.content)
    usages = [result.usage]
    latency_ms = int(result.latency_ms)
    calls = 1
    repaired = False
    if errors:
        repair_user = _repair_user(user, errors, nonce=built.prompt.nonce)
        result = adapter.complete(system=system, user=repair_user, model=model)
        parsed, errors = _parse(schema_name, result.content)
        usages.append(result.usage)
        latency_ms += int(result.latency_ms)
        calls = 2
        repaired = True
    return Proposal(
        content=result.content,
        parsed=None if errors else parsed,
        schema_errors=list(errors),
        repaired=repaired,
        usage=_sum_usage(usages),
        model=result.model,
        latency_ms=latency_ms,
        calls=calls,
    )


def propose(adapter: Any, built: BuiltTriagePrompt, *, cfg: Config) -> Proposal:
    """The ① proposer call against `triage_v2` with `cfg.LLM_MODEL_PROPOSER`."""
    return _call(adapter, built, schema_name="triage_v2", model=cfg.LLM_MODEL_PROPOSER)


def verify(adapter: Any, built: BuiltTriagePrompt, *, cfg: Config) -> Verification:
    """The verifier call (gate step 6) against `verifier_v1` with `cfg.LLM_MODEL_VERIFIER`."""
    return _call(adapter, built, schema_name="verifier_v1", model=cfg.LLM_MODEL_VERIFIER)


# ─────────────────────────────────────────────────────────── prompt_version (design note 6)
_GIT_REV: str | None = None  # `git rev-parse --short HEAD`, once per process; "nogit" on failure
_PROMPT_VERSION_CACHE: dict[Path, str] = {}


def _git_rev(cwd: Path) -> str:
    global _GIT_REV
    if _GIT_REV is None:
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            rev = proc.stdout.strip()
            _GIT_REV = rev if proc.returncode == 0 and rev else "nogit"
        except (OSError, subprocess.SubprocessError):  # no binary, no repository, a hang
            _GIT_REV = "nogit"
    return _GIT_REV


def prompt_version(template: Path) -> str:
    """`"<git short rev at first call>+<sha256 hex of the template bytes>"`, `"nogit+…"`
    without a repository; cached per process, keyed by template path."""
    template = Path(template)
    cached = _PROMPT_VERSION_CACHE.get(template)
    if cached is not None:
        return cached
    version = f"{_git_rev(template.parent)}+{hashlib.sha256(template.read_bytes()).hexdigest()}"
    _PROMPT_VERSION_CACHE[template] = version
    return version
