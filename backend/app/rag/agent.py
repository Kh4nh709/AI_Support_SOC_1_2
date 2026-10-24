"""One call to DeepSeek that must answer a JSON schema: the part every RAG agent shares (P13-T03).

The ranking agent (`rag.match`) uses it now; the drafting agent (P13-T04) uses it with its own schema.
The shape is `llm/investigate.investigate`'s, for any schema of `rag/schemas.json`:

* the user message is linted before the call — everything outside an untrusted block must be a
  template constant, an enum value, a number or an id — and a violation is a `PermanentError` that
  names the kind and the line and never the text; the repair message is linted the same way;
* one call, and at most one repair naming only the failing fields (`llm.builder.SENTENCE_REPAIR`),
  each as a value-free bullet: an index becomes `[]`, and an unexpected key is reported against its
  parent, because the key is the model's own text;
* a second failure is not retried: the result carries `parsed=None` and the errors.

`model` is passed on every call (`rag_model(cfg)`: `RAG_MODEL`, else the proposer's). The deadline is
not: it comes from the adapter's limits (`rag.budget.rag_limits`), so the call and its repair run under
one view of them.

`Tape` wraps any adapter and remembers what was sent and what was paid for, answered or not — the job
needs the prompt to write its `llm_runs` row and the cost of a call whose repair then failed, and
`call_json` returns neither when it raises (the S7 lesson of `tier2/investigate.py`).
"""

from __future__ import annotations

import functools
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.infra.config import Config
from app.infra.errors import PermanentError, TransientError
from app.llm import schemas
from app.llm.builder import (
    BULLET,
    ENUM_VALUES,
    HEADING_REPAIR,
    SENTENCE_REPAIR,
    TEMPLATE_CONSTANTS,
)
from app.llm.investigate import Spend
from app.security import linter

SCHEMAS_PATH = Path(__file__).resolve().parent / "schemas.json"
_JSON_OBJECT = {"type": "json_object"}

_ROOT = "<root>"
_ROOT_ERROR = f"{_ROOT}: expected a JSON object"
_ARRAY_INDEX = re.compile(r"\[\d+\]")
_ENUM_TOKEN = re.compile(r"^[a-z_]+$")

#: `llm/schemas.py`'s value-free message vocabulary (its module docstring), as `llm/investigate.py`
#: and `llm/triage.py` carry it.
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


@dataclass(frozen=True)
class AgentResult:
    """What one `call_json` came to. `parsed` is the schema-valid object, or None after the repair
    failed; `usage`, `latency_ms` are summed over the calls made; `model` is the last call's."""

    parsed: dict | None
    schema_errors: list[str]
    usage: dict
    model: str | None
    latency_ms: int


def rag_model(cfg: Config) -> str:
    """The model every RAG call asks for: `RAG_MODEL`, else the proposer's (spec §7.1)."""
    return cfg.RAG_MODEL or cfg.LLM_MODEL_PROPOSER


# ── the schemas ───────────────────────────────────────────────────────────────────────────────


def load_schemas() -> dict[str, Any]:
    """`{schema_name: node}` as `rag/schemas.json` holds them, in the notation `llm.schemas` reads."""
    return json.loads(SCHEMAS_PATH.read_text(encoding="utf-8"))


def schema_node(name: str) -> Any:
    """The node of schema `name`; `PermanentError` for a name the file does not hold."""
    try:
        return load_schemas()[name]
    except KeyError:
        raise PermanentError(f"unknown RAG schema {name!r}") from None


# ── the repair vocabulary: value-free, so the linter knows every word of it ───────────────────


def _schema_paths(node: Any, prefix: str, paths: dict[str, str], vocabularies: set[str]) -> None:
    """Every dotted path of a schema -> its kind (`object` | `array` | `leaf`), arrays in the `[]`
    form, and every enum leaf's `expected one of …` message. `llm/investigate.py` and
    `llm/triage.py` walk their schemas the same way."""
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
            if "string" not in alternatives and all(_ENUM_TOKEN.fullmatch(a) for a in values):
                vocabularies.add(f"expected one of {'|'.join(values)}")


@functools.cache
def _repair_vocabulary(name: str) -> tuple[dict[str, str], frozenset[str]]:
    paths: dict[str, str] = {}
    vocabularies: set[str] = set()
    _schema_paths(schema_node(name), "", paths, vocabularies)
    constants = {f"{path}:" for path in paths} | {f"{_ROOT}:"} | _MESSAGE_CONSTANTS | vocabularies
    return paths, frozenset(constants)


def repair_constants(name: str) -> frozenset[str]:
    """The words a repair message for schema `name` is made of (beyond `TEMPLATE_CONSTANTS`)."""
    return _repair_vocabulary(name)[1]


def _object_prefix(path: str, paths: Mapping[str, str]) -> str:
    """The longest known *object* prefix of `path`: the parent of an `unexpected key`, whatever
    the key contains (it is the model's, so it may carry dots)."""
    while path and paths.get(path) != "object":
        path = path.rsplit(".", 1)[0] if "." in path else ""
    return path


def _repair_line(error: str, paths: Mapping[str, str]) -> str:
    path, _, message = error.partition(": ")
    path = _ARRAY_INDEX.sub("[]", path)
    if message == "unexpected key":
        path = _object_prefix(path, paths)
    return f"{BULLET}{path or _ROOT}: {message}"


# ── the call ──────────────────────────────────────────────────────────────────────────────────


def _lint_or_raise(
    user: str, *, nonce: str, schema_name: str, extra_constants: frozenset[str]
) -> None:
    """A violation is a template defect, never a model outcome: the call is not made."""
    violations = linter.lint(
        user,
        nonce=nonce,
        constants=TEMPLATE_CONSTANTS | repair_constants(schema_name) | extra_constants,
        enums=ENUM_VALUES,
    )
    if violations:
        first = violations[0]
        raise PermanentError(
            f"rag prompt failed the linter: {first.kind} at line {first.line} "
            f"({len(violations)} violation(s))"
        )


def _parse(content: str, schema_name: str) -> tuple[dict | None, list[str]]:
    try:
        parsed = json.loads(content)
    except (ValueError, RecursionError):
        return None, [_ROOT_ERROR]
    if not isinstance(parsed, dict):
        return None, [_ROOT_ERROR]
    return parsed, schemas.validate_against(schema_node(schema_name), parsed)


def call_json(
    adapter: Any,
    *,
    system: str,
    user: str,
    nonce: str,
    schema_name: str,
    extra_constants: frozenset[str],
    model: str,
    cfg: Config,
) -> AgentResult:
    """One call against schema `schema_name`, at most one repair (module doc).

    `LLMTimeout`, `LLMBudgetExceeded` and `LLMPermanent` (`app.llm.adapter`) are not caught: they
    reach the job, which holds the connection to record them against. `extra_constants` is what the
    caller's own template adds to the vocabulary the linter accepts outside a block."""
    del cfg  # the signature of `llm.investigate.investigate`; the limits are the adapter's
    schema = schema_name
    paths, _ = _repair_vocabulary(schema)  # an unknown name stops here, before any call
    _lint_or_raise(user, nonce=nonce, schema_name=schema, extra_constants=extra_constants)

    spend = Spend()
    result = adapter.complete(
        system=system, user=user, response_format=_JSON_OBJECT, model=model or None
    )
    spend.record(result)
    parsed, errors = _parse(result.content, schema)

    if errors:
        suffix = "\n".join(
            (HEADING_REPAIR, SENTENCE_REPAIR, *(_repair_line(e, paths) for e in errors))
        )
        repair_user = f"{user}\n\n{suffix}"
        _lint_or_raise(
            repair_user, nonce=nonce, schema_name=schema, extra_constants=extra_constants
        )
        result = adapter.complete(
            system=system, user=repair_user, response_format=_JSON_OBJECT, model=model or None
        )
        spend.record(result)
        parsed, errors = _parse(result.content, schema)

    return AgentResult(
        parsed=None if errors else parsed,
        schema_errors=list(errors),
        usage=spend.usage,
        model=spend.model,
        latency_ms=spend.latency_ms,
    )


# ── what was sent, what was paid for ──────────────────────────────────────────────────────────


class Tape:
    """An adapter that remembers its calls. `sent` holds `(system, user)` of every call attempted,
    in order, answered or not; `calls`, `usage`, `latency_ms` and `model` describe the answered
    ones (what the provider billed). Every argument is passed through untouched."""

    def __init__(self, adapter: Any) -> None:
        self._adapter = adapter
        self._spend = Spend()
        self.sent: list[tuple[str, str]] = []

    def complete(self, *, system: str, user: str, **kwargs: Any) -> Any:
        self.sent.append((system, user))
        result = self._adapter.complete(system=system, user=user, **kwargs)
        self._spend.record(result)
        return result

    @property
    def calls(self) -> int:
        return self._spend.calls

    @property
    def usage(self) -> dict[str, Any]:
        return self._spend.usage

    @property
    def latency_ms(self) -> int:
        return self._spend.latency_ms

    @property
    def model(self) -> str | None:
        return self._spend.model


def is_transient(exc: BaseException) -> bool:
    """Whether a failed model call is worth another attempt of the job: a `TransientError` (the
    deadline, `LLMTimeout`), a transport error, or an HTTP status >= 500 (the adapter re-raises the
    provider's error, carrying `.status_code`, once its own retries are spent). Not
    `infra.errors.classify`, which counts an unclassified exception as a side effect: an exception
    this does not recognise is a bug, and the job lets it through untouched."""
    if isinstance(exc, (TransientError, httpx.TransportError)):
        return True
    status = getattr(exc, "status_code", None)
    if not isinstance(status, int):
        status = getattr(getattr(exc, "response", None), "status_code", None)
    return isinstance(status, int) and status >= 500
