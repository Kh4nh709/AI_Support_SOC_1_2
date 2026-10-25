"""Pipeline ②: the single-shot investigation call against the case dossier.

P5-T04 (DEC-151 wave 3). Pure: no database, no tier import — `llm` may import only
`security`, `infra`, `kb` (context pack §4), so this module never imports
`app.tier2.dossier`. `build()`/`investigate()` take a duck-typed dossier (`.text`,
`.nonce` — the two attributes read here; a real `app.tier2.dossier.Dossier` satisfies
this structurally, and so does a small test double with the same attributes).

Mirrors `llm/triage.py`'s propose()/verify() shape (design note 2's "the prompt-build
-> send -> one-repair -> validate shape you mirror"): one call against `investigate_v2`
(`app.llm.schemas`), at most one repair naming only the failing fields
(`llm.builder.SENTENCE_REPAIR`), take whatever comes back. `tier2/investigate.py` (the
job) is the only caller and the only writer of `llm_runs` — this module returns a plain
result object and touches no connection, no adapter it did not receive.

The one place this module cannot fully mirror ①: `llm/triage.py`'s repair-turn lints
the assembled prompt against its OWN `PromptBuilder`-built vocabulary; a dossier's
vocabulary (`tier2.dossier.DOSSIER_TEMPLATE_CONSTANTS`) lives in a package this module
may not import (G1). `investigate()` therefore takes `extra_constants` — the caller
(`tier2/investigate.py`, which may import both `tier2.dossier` and this module) passes
`DOSSIER_TEMPLATE_CONSTANTS` through it. `tier2/dossier.py`'s own docstring anticipates
exactly this caller ("combined with the builder's own set by any caller ... later
P5-T04").
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from app.infra.config import Config
from app.infra.errors import PermanentError
from app.llm import schemas
from app.llm.builder import (
    BULLET,
    ENUM_VALUES,
    HEADING_REPAIR,
    SENTENCE_REPAIR,
    TEMPLATE_CONSTANTS,
)
from app.security import linter

TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "investigate_system.txt"
SCHEMA_NAME = "investigate_v2"


class DossierLike(Protocol):
    """The two attributes this module reads off a dossier. Never
    `app.tier2.dossier.Dossier` by import (G1) — see the module docstring."""

    text: str
    nonce: str


def _system_prompt() -> str:
    """The template plus the rendered §6.2 schema — `llm/triage.py::_system_prompt`'s
    shape, part of the "prompt-build" half of design note 2's shape to mirror: giving
    the model the exact field vocabulary lowers the first-attempt schema-failure rate
    the repair round exists to catch. The template file alone already carries the
    literal word "JSON" the adapter requires (acceptance 2); this appends more of it
    (the schema render is JSON-shaped text), never removes it."""
    text = TEMPLATE_PATH.read_text("utf-8")
    return f"{text}\n\n## Schema {SCHEMA_NAME}\n{schemas.render(SCHEMA_NAME)}"


def build(dossier: DossierLike, *, nonce: str, cfg: Config | None = None) -> tuple[str, str]:
    """(system, user). The user message is `dossier.text` verbatim: P5-T03's dossier is
    already a fully rendered, nonce-wrapped prompt, and this module adds nothing to it
    outside the separate repair turn `investigate()` builds. `nonce` and `cfg` are part
    of the card's documented signature; `nonce` must be the same value the dossier was
    built with (the caller's contract, `tier2/investigate.py`'s), and `cfg` is accepted
    for signature parity with `investigate()` though `build()` itself reads nothing off
    it — pure, no I/O beyond reading the template file."""
    del cfg
    return _system_prompt(), dossier.text


# --------------------------------------------------------------------------- the
# repair round (mirrors llm/triage.py's "the repair round", design note 5 there):
# a value-free vocabulary derived from investigate_v2's own §6.2 shape, so the
# repair turn's bullets are template constants the linter already knows, never
# free text a validator message happened to contain.
# ---------------------------------------------------------------------------

_ROOT = "<root>"
_ROOT_ERROR = f"{_ROOT}: expected a JSON object"
_ARRAY_INDEX_RE = re.compile(r"\[\d+\]")
_ENUM_TOKEN_RE = re.compile(r"^[a-z_]+$")

#: `llm/schemas.py`'s value-free message vocabulary (its module docstring) — the same
#: fixed set `llm/triage.py`'s `_MESSAGE_CONSTANTS` carries, duplicated rather than
#: imported (that name is private to `llm.triage`, and this module mirrors the shape,
#: not the file).
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
    """Every dotted path of the `investigate_v2` schema -> its kind (`object` | `array`
    | `leaf`), arrays in the rendered `[]` form; every enum leaf's `expected one of …`
    message. Identical algorithm to `llm/triage.py::_schema_paths` (design note 2:
    mirror ①'s shape), applied to one schema instead of two."""
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


def _repair_vocabulary(name: str) -> tuple[dict[str, str], frozenset[str]]:
    paths: dict[str, str] = {}
    vocabularies: set[str] = set()
    _schema_paths(schemas.load()[name], "", paths, vocabularies)
    constants = {f"{path}:" for path in paths} | {f"{_ROOT}:"} | _MESSAGE_CONSTANTS | vocabularies
    return paths, frozenset(constants)


_SCHEMA_PATHS, REPAIR_CONSTANTS = _repair_vocabulary(SCHEMA_NAME)


def _object_prefix(path: str) -> str:
    """The longest known *object* prefix of `path` — the parent of an `unexpected key`,
    whatever the key itself contains (it is the model's, so it may carry dots)."""
    while path and _SCHEMA_PATHS.get(path) != "object":
        path = path.rsplit(".", 1)[0] if "." in path else ""
    return path


#: The suffix `llm.schemas.validate` gives a key the schema does not have: `<path of the key>: unexpected key`.
_UNEXPECTED_KEY = ": unexpected key"


def _repair_line(error: str) -> str:
    """One validator message -> one value-free bullet: array indices normalised to the
    schema's `[]` form; an `unexpected key` reported against its parent object, never
    the key itself (which is the model's own text, not a template constant).

    The key is the model's, so it may itself contain `": "` (`a: b`, `summary: missing`). A split at
    the first `": "` then left part of it in the bullet, outside any block, where the linter refused
    the repair (P13-T08, the same finding as `rag/agent.py`'s, fixed there in P13-T03). The suffix is
    therefore taken off first, from the end; what is left is the key's path, of which only the longest
    known object prefix is kept. Every other message has a path the schema owns, and splits where it
    always did."""
    if error.endswith(_UNEXPECTED_KEY):
        parent = _object_prefix(_ARRAY_INDEX_RE.sub("[]", error[: -len(_UNEXPECTED_KEY)]))
        return f"{BULLET}{parent or _ROOT}{_UNEXPECTED_KEY}"
    path, _, message = error.partition(": ")
    path = _ARRAY_INDEX_RE.sub("[]", path)
    return f"{BULLET}{path or _ROOT}: {message}"


def _lint_or_raise(user: str, *, nonce: str, extra_constants: frozenset[str]) -> None:
    """G6′, "at test time and before every send" (design note 2). A violation is a
    `PermanentError` naming the line — a template defect, never a model outcome, so
    the call is not made."""
    violations = linter.lint(
        user,
        nonce=nonce,
        constants=TEMPLATE_CONSTANTS | REPAIR_CONSTANTS | extra_constants,
        enums=ENUM_VALUES,
    )
    if violations:
        first = violations[0]
        raise PermanentError(
            f"investigate prompt failed the linter: {first.kind} at line {first.line} "
            f"({len(violations)} violation(s))"
        )


def _repair_user(
    user: str, errors: list[str], *, nonce: str, extra_constants: frozenset[str]
) -> str:
    suffix = "\n".join((HEADING_REPAIR, SENTENCE_REPAIR, *(_repair_line(e) for e in errors)))
    repair_user = f"{user}\n\n{suffix}"
    _lint_or_raise(repair_user, nonce=nonce, extra_constants=extra_constants)
    return repair_user


def _parse(content: str) -> tuple[dict | None, list[str]]:
    try:
        parsed = json.loads(content)
    except ValueError:  # json.JSONDecodeError
        return None, [_ROOT_ERROR]
    if not isinstance(parsed, dict):
        return None, [_ROOT_ERROR]
    parsed = schemas.normalise(SCHEMA_NAME, parsed)
    return parsed, schemas.validate(SCHEMA_NAME, parsed)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _sum_usage(usages: list[dict[str, Any]]) -> dict[str, Any]:
    """Key-wise sum over the calls made (`llm/triage.py::_sum_usage`'s shape) — a
    non-numeric value is carried through, never added."""
    total: dict[str, Any] = {}
    for usage in usages:
        for key, value in usage.items():
            current = total.get(key)
            if _is_number(value) and _is_number(current):
                total[key] = current + value
            elif _is_number(value) or key not in total:
                total[key] = value
    return total


@dataclass
class Spend:
    """Every paid call `investigate()` made so far, carried out to the caller even when
    a later call raises (review round 1, S7). A call that fails *after* an earlier one
    was answered — the repair turn timing out, or the repair prompt failing the linter —
    still cost the first call's tokens; the exception discards `InvestigateResult`, so
    without this the job would write that attempt's row with no usage and no cost and
    the month-to-date cap (`audit.llm_runs.month_spend_usd`) would under-count. Follows
    ①'s pattern in `tier1/triage.py` ("the proposer's usage is recorded even when the
    verifier fails"). A call that itself raised has no usage to record: it is simply
    not here."""

    usages: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: int = 0
    model: str | None = None

    def record(self, result: Any) -> None:
        self.usages.append(result.usage)
        self.latency_ms += int(result.latency_ms)
        self.model = result.model

    @property
    def calls(self) -> int:
        return len(self.usages)

    @property
    def usage(self) -> dict[str, Any]:
        return _sum_usage(self.usages)


@dataclass(frozen=True)
class InvestigateResult:
    content: str  # the last call's `choices[0].message.content`, verbatim
    parsed: dict | None  # the schema-valid object, or None after the repair round failed
    schema_errors: list[str]  # the last call's validation errors ([] when `parsed` is set)
    repaired: bool
    usage: dict  # summed over the calls made
    model: str  # from the last call
    latency_ms: int  # summed over the calls made
    calls: int  # 1 or 2 — never 3 (design note 2: "one repair and no more")


def investigate(
    adapter: Any,
    dossier: DossierLike,
    *,
    nonce: str,
    cfg: Config,
    extra_constants: frozenset[str] = frozenset(),
    spend: Spend | None = None,
) -> InvestigateResult:
    """One call against `investigate_v2`, at most one repair. `response_format={"type":
    "json_object"}` (design note 2); `model` is deliberately not passed — the adapter's
    own default is `cfg.LLM_MODEL_PROPOSER` (there is no separate investigator model in
    §6.3), and the fake adapter every test uses (`backend/tests/fakes/llm.py`) accepts
    no `model` keyword at all.

    `LLMTimeout`, `LLMBudgetExceeded` and `LLMPermanent` (`app.llm.adapter`) are not
    caught here: they propagate to `tier2/investigate.py`, which is the module with a
    connection to record them against (design note 3(d)). `spend`, when given, receives
    every *answered* call as it is made — so the caller still sees what the first call
    cost when the repair call (or the repair prompt's own lint) raises (S7).

    **The deadline is not passed** (P11-T03): `timeout_s` is left to the adapter, which takes
    it from its `limits` (the admin's saved `LLM_TIMEOUT_S`, else `.env`, read per attempt and
    fail-closed), so nothing here reads the config's timeout and the call and its one repair
    run under the same limits. `cfg` stays in the signature for the caller's sake."""
    del cfg
    system = _system_prompt()
    user = dossier.text
    _lint_or_raise(user, nonce=nonce, extra_constants=extra_constants)

    result = adapter.complete(
        system=system,
        user=user,
        response_format={"type": "json_object"},
    )
    if spend is not None:
        spend.record(result)
    parsed, errors = _parse(result.content)
    usages = [result.usage]
    latency_ms = int(result.latency_ms)
    calls = 1
    repaired = False

    if errors:
        repair_user = _repair_user(user, errors, nonce=nonce, extra_constants=extra_constants)
        result = adapter.complete(
            system=system,
            user=repair_user,
            response_format={"type": "json_object"},
        )
        if spend is not None:
            spend.record(result)
        parsed, errors = _parse(result.content)
        usages.append(result.usage)
        latency_ms += int(result.latency_ms)
        calls = 2
        repaired = True

    return InvestigateResult(
        content=result.content,
        parsed=None if errors else parsed,
        schema_errors=list(errors),
        repaired=repaired,
        usage=_sum_usage(usages),
        model=result.model,
        latency_ms=latency_ms,
        calls=calls,
    )
