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

``validate(name, obj) -> list[str]``: each message is
``"<dotted.path>: expected <kind or vocabulary>"`` — e.g.
``structured_basis.asset_criticality: expected one of high|medium|low|unknown``,
``reasons[1].source: expected one of wazuh_raw_log|...``. ``reasons`` carries no
``minItems`` in §6.2, so an empty list is schema-valid — that is not a bug in this
module, it is the contract (gate step 3 handles "zero reasons left" separately).
**A message never contains the offending value** (planning decision 9: the repair
prompt quotes these messages outside a block, and the value may be attacker
controlled). An unknown schema ``name`` raises ``KeyError``.

``render(name) -> str`` renders the schema for a system prompt: one line per field,
``path: vocabulary|kind``, nested objects indented two spaces, arrays as
``path[]: ...``. Two calls on the same file produce identical bytes.
"""

from __future__ import annotations

import json
import re
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


def validate(name: str, obj: Any) -> list[str]:
    """Every way ``obj`` departs from the ``name`` schema, value-free.

    An empty list means valid. ``name`` not in ``output_schemas.json`` → ``KeyError``.
    """
    schema = _get_schema(name)
    return _validate_node("", schema, obj)


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
