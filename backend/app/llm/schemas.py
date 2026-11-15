"""backend/app/llm/schemas.py — loads and validates against §6.2's LLM output schemas.

``backend/app/llm/templates/output_schemas.json`` is the only source (context pack
§6.2); this module never hand-transcribes a second copy of the shapes it validates.
No third-party JSON-schema validator is imported — the obvious one is installed on
this host but absent from ``backend/requirements.txt``, so importing it would pass
here and fail from a clean checkout. The interpreter below is written by hand.

§6.2's compact notation, read node by node — this is the whole interpreter:

    §6.2 value                          means                  validation
    -----------------------------------  ---------------------  --------------------------------
    "a|b|c" (every alternative matches   enum                   value must be a str in the set;
    ^[a-z_]+$, none is "string")                                "null" among the alternatives
                                                                 admits None
    "string"                             free string            str
    "string|null"                        nullable string        str or None
    any other string (contains a space)  free string with a     str
                                          human note
    0                                    integer                int and not bool
    true / false                         boolean                bool
    {...}                                object                 dict; every key required,
                                                                 no extra keys
    [x]                                  array of x             list, each item validated as x;
                                                                 minItems 1 when the note says so
                                                                 ("string (minItems 1)" -> a
                                                                 non-empty list of str)

``validate_against(schema, obj) -> list[str]`` is the same validator over a node it is given
(P13-T03: the RAG schemas live in ``backend/app/rag/schemas.json``, not in this module's file).

``validate(name, obj) -> list[str]``: each message is
``"<dotted.path>: expected <kind or vocabulary>"`` — e.g.
``structured_basis.asset_criticality: expected one of high|medium|low|unknown``,
``reasons[1].source: expected one of wazuh_raw_log|...``. ``reasons`` carries no
``minItems`` in §6.2, so an empty list is schema-valid — that is not a bug in this
module, it is the contract (gate step 3 handles "zero reasons left" separately).
**A message never contains the offending value** (planning decision 9: the repair
prompt quotes these messages outside a block, and the value may be attacker
controlled). An unknown schema ``name`` raises ``KeyError``.

``normalise(name, obj) -> obj`` runs before ``validate`` (``llm/triage.py`` ``_parse``):
a JSON boolean at an enum leaf whose vocabulary spells it — only
``structured_basis.identity_privileged: true|false|unknown`` — becomes that string.
The rendered vocabulary reads as JSON literals, and the model answers ``true``, not
``"true"`` (P7-T09). Every other mismatch is left for ``validate`` to report.

``render(name) -> str`` renders the schema for a system prompt: one line per field,
``path: vocabulary|kind``, nested objects indented two spaces, arrays as
``path[]: ...``. Two calls on the same file produce identical bytes.

``json_schema(name) -> dict`` (DEC-218) is the same notation read as a JSON Schema, for a provider that
enforces the output shape (``response_format: json_schema``); ``json_schema_of(node)`` is it over a
node it is given. Written by hand like the interpreter, from the same file, so there is still one source:

    §6.2 value                          JSON Schema
    -----------------------------------  ---------------------------------------------------------
    {...}                                object; every key in ``required`` (file order), no others
    [x]                                  array of x; ``minItems: 1`` where the note says so
    "a|b|c" (an enum)                    ``{"type": "string", "enum": [...]}``; with "null" among the
                                         alternatives ``{"type": ["string", "null"], "enum": [..., null]}``
    "string" / a free string with note   ``{"type": "string"}``
    "string|null"                        ``{"type": ["string", "null"]}``
    0                                    ``{"type": "integer"}``
    true / false                         ``{"type": "boolean"}``

``structured_basis.identity_privileged`` stays the string enum ``true|false|unknown``; ``normalise``
turns a JSON boolean into it, and the schema the provider enforces asks for the string.

JSON Schema's ``integer`` is looser than the ``0`` row above: it admits an integer-valued number such as
``1.0``, which ``validate`` still refuses (an ``int`` and not a ``bool``; ``json.loads`` reads ``1.0`` as a
float). That is by design: the validator is the check behind the provider, and the repair round covers
whatever a provider lets through.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
SCHEMAS_PATH = TEMPLATES_DIR / "output_schemas.json"

_ENUM_TOKEN = re.compile(r"^[a-z_]+$")


def load(path: Path = SCHEMAS_PATH) -> dict[str, Any]:
    """Parse ``output_schemas.json`` — ``{schema_name: schema_node, ...}``.

    Nothing here catches a malformed file; a bad transcription fails loudly.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def _get_schema(name: str) -> Any:
    """The schema node for ``name``. Raises ``KeyError`` for an unknown name."""
    return load()[name]


# ---------------------------------------------------------------------------
# string-spec classification — the single place that reads §6.2's compact
# string notation (enum / "string" / "string|null" / free-string-with-note).
# ---------------------------------------------------------------------------


def _classify_string_spec(spec: str) -> tuple[str, Any]:
    """Return (kind, extra) for a leaf string spec.

    kind is one of "enum", "string", "nullable_string", "note_string".
    extra is (values, nullable) for "enum", else None.
    """
    alternatives = spec.split("|")
    if "string" not in alternatives and all(_ENUM_TOKEN.fullmatch(a) for a in alternatives):
        nullable = "null" in alternatives
        values = tuple(a for a in alternatives if a != "null")
        if values:
            return "enum", (values, nullable)
    if spec == "string":
        return "string", None
    if spec == "string|null":
        return "nullable_string", None
    return "note_string", None  # free string with a human-readable annotation


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _validate_node(path: str, node: Any, value: Any) -> list[str]:
    if isinstance(node, dict):
        return _validate_object(path, node, value)
    if isinstance(node, list):
        return _validate_array(path, node, value)
    if isinstance(node, bool):  # must precede the int check — bool is an int subclass
        if not isinstance(value, bool):
            return [f"{path}: expected boolean"]
        return []
    if isinstance(node, int):
        if isinstance(value, bool) or not isinstance(value, int):
            return [f"{path}: expected integer"]
        return []
    if isinstance(node, str):
        return _validate_string_spec(path, node, value)
    raise AssertionError(f"unrecognised §6.2 schema node at {path!r}: {node!r}")


def _validate_object(path: str, fields: dict[str, Any], value: Any) -> list[str]:
    if not isinstance(value, dict):
        return [f"{path}: expected object"]
    problems: list[str] = []
    for key, sub in fields.items():
        sub_path = _join(path, key)
        if key not in value:
            problems.append(f"{sub_path}: missing")
            continue
        problems.extend(_validate_node(sub_path, sub, value[key]))
    for key in value:
        if key not in fields:
            problems.append(f"{_join(path, key)}: unexpected key")
    return problems


def _validate_array(path: str, spec: list[Any], value: Any) -> list[str]:
    assert len(spec) == 1, f"§6.2 array node at {path!r} must carry exactly one item spec"
    item_spec = spec[0]
    min_items_one = isinstance(item_spec, str) and "(minitems 1)" in item_spec.lower()
    if not isinstance(value, list):
        return [f"{path}: expected array"]
    problems: list[str] = []
    if min_items_one and len(value) == 0:
        problems.append(f"{path}: expected non-empty array")
    for index, item in enumerate(value):
        problems.extend(_validate_node(f"{path}[{index}]", item_spec, item))
    return problems


def _validate_string_spec(path: str, spec: str, value: Any) -> list[str]:
    kind, extra = _classify_string_spec(spec)
    if kind == "enum":
        values, nullable = extra
        if nullable and value is None:
            return []
        if not isinstance(value, str) or value not in values:
            return [f"{path}: expected one of {'|'.join(values)}"]
        return []
    if kind == "nullable_string":
        if value is not None and not isinstance(value, str):
            return [f"{path}: expected string or null"]
        return []
    # "string" and "note_string" (free string with a human note) both need only str.
    if not isinstance(value, str):
        return [f"{path}: expected string"]
    return []


def validate_against(schema: Mapping[str, Any], obj: Any) -> list[str]:
    """``validate`` over a given node: every way ``obj`` departs from ``schema``, value-free.

    ``schema`` is a node in the §6.2 notation above (an object node, as ``validate`` reads from
    ``output_schemas.json``), taken from anywhere — ``rag/schemas.json`` holds the RAG ones. The
    messages are the same as ``validate``'s, and an empty list means valid.
    """
    return _validate_node("", schema, obj)


def validate(name: str, obj: Any) -> list[str]:
    """Every way ``obj`` departs from the ``name`` schema, value-free.

    An empty list means valid. ``name`` not in ``output_schemas.json`` → ``KeyError``.
    """
    return validate_against(_get_schema(name), obj)


# ---------------------------------------------------------------------------
# normalise()
# ---------------------------------------------------------------------------


def _normalise_node(node: Any, value: Any) -> Any:
    if isinstance(node, dict) and isinstance(value, dict):
        return {k: _normalise_node(node[k], v) if k in node else v for k, v in value.items()}
    if isinstance(node, list) and isinstance(value, list):
        return [_normalise_node(node[0], item) for item in value]
    if isinstance(node, str) and isinstance(value, bool):
        kind, extra = _classify_string_spec(node)
        spelled = "true" if value else "false"
        if kind == "enum":
            values, _nullable = extra
            if spelled in values:
                return spelled
    return value


def normalise(name: str, obj: Any) -> Any:
    """A copy of ``obj`` with the JSON booleans the ``name`` vocabulary spells as strings.

    The set of accepted values is unchanged; every other mismatch is left for ``validate``.
    ``name`` not in ``output_schemas.json`` → ``KeyError``.
    """
    return _normalise_node(_get_schema(name), obj)


# ---------------------------------------------------------------------------
# render()
# ---------------------------------------------------------------------------


def _describe_leaf(spec: Any) -> str:
    if isinstance(spec, bool):
        return "boolean"
    if isinstance(spec, int):
        return "integer"
    if isinstance(spec, str):
        kind, extra = _classify_string_spec(spec)
        if kind == "enum":
            values, nullable = extra
            vocab = "|".join(values)
            return f"{vocab}|null" if nullable else vocab
        if kind == "nullable_string":
            return "string|null"
        return "string"  # "string" and note_string both render as bare "string"
    raise AssertionError(f"not a leaf §6.2 node: {spec!r}")


def _render_fields(fields: dict[str, Any], indent: int, lines: list[str]) -> None:
    pad = "  " * indent
    for key, spec in fields.items():
        if isinstance(spec, dict):
            lines.append(f"{pad}{key}:")
            _render_fields(spec, indent + 1, lines)
        elif isinstance(spec, list):
            item_spec = spec[0]
            if isinstance(item_spec, dict):
                lines.append(f"{pad}{key}[]:")
                _render_fields(item_spec, indent + 1, lines)
            else:
                lines.append(f"{pad}{key}[]: {_describe_leaf(item_spec)}")
        else:
            lines.append(f"{pad}{key}: {_describe_leaf(spec)}")


def render(name: str) -> str:
    """The ``name`` schema rendered for a system prompt — deterministic bytes.

    ``name`` not in ``output_schemas.json`` → ``KeyError``.
    """
    schema = _get_schema(name)
    lines: list[str] = []
    _render_fields(schema, 0, lines)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# json_schema()
# ---------------------------------------------------------------------------


def _json_schema_node(node: Any) -> dict[str, Any]:
    if isinstance(node, dict):
        return {
            "type": "object",
            "properties": {key: _json_schema_node(sub) for key, sub in node.items()},
            "required": list(node),
            "additionalProperties": False,
        }
    if isinstance(node, list):
        assert len(node) == 1, "§6.2 array node must carry exactly one item spec"
        item_spec = node[0]
        array: dict[str, Any] = {"type": "array", "items": _json_schema_node(item_spec)}
        if isinstance(item_spec, str) and "(minitems 1)" in item_spec.lower():
            array["minItems"] = 1
        return array
    if isinstance(node, bool):  # must precede the int check — bool is an int subclass
        return {"type": "boolean"}
    if isinstance(node, int):
        return {"type": "integer"}
    if isinstance(node, str):
        kind, _extra = _classify_string_spec(node)
        if kind == "enum":
            alternatives = [None if a == "null" else a for a in node.split("|")]
            nullable = None in alternatives
            return {"type": ["string", "null"] if nullable else "string", "enum": alternatives}
        if kind == "nullable_string":
            return {"type": ["string", "null"]}
        return {"type": "string"}  # "string" and note_string (free string with a human note)
    raise AssertionError(f"unrecognised §6.2 schema node: {node!r}")


def json_schema_of(schema: Mapping[str, Any]) -> dict[str, Any]:
    """The JSON Schema of a node in the §6.2 notation (see the module docstring), a fresh dict each call."""
    return _json_schema_node(schema)


def json_schema(name: str) -> dict[str, Any]:
    """The JSON Schema of the ``name`` schema of ``output_schemas.json``. ``name`` not in the file → ``KeyError``."""
    return json_schema_of(_get_schema(name))
