"""P11-T14: the rule builder of the React admin console offers only what the server accepts.

`frontend/src/features/admin/ruleFields.ts` holds a typed copy of `autoclose._WHITELIST` (field -> allowed
operators) and the scalar type of each field, so the condition builder can only offer a field/operator pair
`autoclose._parse_match` accepts. A copy can drift: this test reads the TypeScript file as TEXT (there is
no TypeScript toolchain in the backend suite and none is needed) and compares it with the server:

- every field, and for each field its set of operators, equals `_WHITELIST` (an operator the UI offers that
  the server refuses, or one the server accepts that the UI forgot, fails);
- every scalar type (`string` | `integer` | `boolean`) equals what `_scalar_ok` accepts for that field,
  found by probing the function itself (it is code, not a table);
- the operator vocabulary and the shape of the value each operator takes (`eq` one scalar, `in` a
  non-empty list, `cidr` a network, `prefix` any string, `lte` an integer) equal `_value_ok`'s.

Non-db: it reads two files and calls pure functions. Shown red in the P11-T14 report by adding a pair to
the TypeScript file (`identity_privileged` gaining `in`), then restoring it.
"""

from __future__ import annotations

import pathlib
import re

from app.ingest import autoclose

RULE_FIELDS_TS = (
    pathlib.Path(__file__).resolve().parents[2]
    / "frontend"
    / "src"
    / "features"
    / "admin"
    / "ruleFields.ts"
)


def _ts_text() -> str:
    """The source with its comments removed, so a field name inside a comment is never read as data."""
    text = RULE_FIELDS_TS.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"(?m)//.*$", "", text)


def _block(text: str, name: str) -> str:
    """The body of `export const <name> = { ... }` (or `[ ... ]`), found by name and balanced braces."""
    match = re.search(rf"export const {name}\b[^=]*=\s*([{{\[])", text)
    assert match is not None, f"ruleFields.ts has no `export const {name}`"
    opener = match.group(1)
    closer = "}" if opener == "{" else "]"
    start = match.end()
    depth = 1
    i = start
    while depth:
        assert i < len(text), f"`{name}` is never closed"
        if text[i] == opener:
            depth += 1
        elif text[i] == closer:
            depth -= 1
        i += 1
    return text[start : i - 1]


def _strings(chunk: str) -> list[str]:
    return re.findall(r'"([^"]*)"', chunk)


def _ts_whitelist() -> dict[str, tuple[str, list[str]]]:
    """`RULE_WHITELIST`: field -> (scalar type, operators in the order the file lists them)."""
    body = _block(_ts_text(), "RULE_WHITELIST")
    entry = re.compile(
        r"(\w+)\s*:\s*\{\s*type\s*:\s*\"(\w+)\"\s*,\s*ops\s*:\s*\[([^\]]*)\]\s*,?\s*\}",
    )
    found: dict[str, tuple[str, list[str]]] = {}
    for field, scalar_type, ops in entry.findall(body):
        assert field not in found, f"RULE_WHITELIST lists {field} twice"
        found[field] = (scalar_type, _strings(ops))
    # every `name:` at the top of the block was read: nothing was skipped by a formatting surprise
    assert len(re.findall(r"(?m)^\s*(\w+)\s*:\s*\{", body)) == len(found)
    return found


def _probed_type(field: str) -> str:
    """The scalar type `_scalar_ok` accepts for `field`: exactly one of the three probes passes."""
    probes = {"string": "x", "integer": 443, "boolean": True}
    accepted = [kind for kind, value in probes.items() if autoclose._scalar_ok(field, value)]
    assert len(accepted) == 1, f"{field}: _scalar_ok accepts {accepted}, expected exactly one type"
    return accepted[0]


def test_the_file_is_there_and_lists_fields() -> None:
    # a guard over nothing would pass for nothing
    assert RULE_FIELDS_TS.is_file(), RULE_FIELDS_TS
    assert len(_ts_whitelist()) >= 10


def test_every_field_and_operator_pair_equals_the_servers_whitelist() -> None:
    ts = {field: set(ops) for field, (_type, ops) in _ts_whitelist().items()}
    server = {field: set(ops) for field, ops in autoclose._WHITELIST.items()}
    assert ts == server


def test_no_operator_is_listed_twice_for_a_field() -> None:
    for field, (_type, ops) in _ts_whitelist().items():
        assert len(ops) == len(set(ops)), f"{field}: {ops}"


def test_every_scalar_type_equals_what_the_server_accepts() -> None:
    ts = {field: scalar_type for field, (scalar_type, _ops) in _ts_whitelist().items()}
    server = {field: _probed_type(field) for field in autoclose._WHITELIST}
    assert ts == server


def test_the_operator_vocabulary_is_the_union_of_the_whitelists() -> None:
    declared = set(_strings(_block(_ts_text(), "RULE_OPS")))
    union = set().union(*autoclose._WHITELIST.values())
    assert declared == union


def _ts_value_kinds() -> dict[str, str]:
    body = _block(_ts_text(), "OP_VALUE_KIND")
    return dict(re.findall(r"(\w+)\s*:\s*\"(\w+)\"", body))


def test_the_value_shape_of_each_operator_equals_the_servers() -> None:
    kinds = _ts_value_kinds()
    assert set(kinds) == set().union(*autoclose._WHITELIST.values())
    # a field that takes every shape's scalar: srcip is a string field with eq, in, cidr; agent_name has
    # prefix; rule_level has lte. The probes are values the server's `_value_ok` is asked about directly.
    ok = autoclose._value_ok
    assert kinds["eq"] == "scalar"
    assert (
        ok("category", "eq", "x")
        and not ok("category", "eq", ["x"])
        and not ok("category", "eq", 1)
    )
    assert kinds["in"] == "list"
    assert (
        ok("category", "in", ["x", ""])
        and not ok("category", "in", [])
        and not ok("category", "in", "x")
    )
    assert kinds["cidr"] == "text"
    assert ok("srcip", "cidr", "10.0.0.0/8") and ok("srcip", "cidr", "10.0.0.1")  # a bare IP passes
    assert not ok("srcip", "cidr", "10.0.0.0/33") and not ok("srcip", "cidr", 8)
    assert kinds["prefix"] == "text"
    assert ok("agent_name", "prefix", "lab-") and ok(
        "agent_name", "prefix", ""
    )  # the empty one too
    assert not ok("agent_name", "prefix", 5)
    assert kinds["lte"] == "integer"
    assert ok("rule_level", "lte", 7) and not ok("rule_level", "lte", True)
    assert not ok("rule_level", "lte", "7") and not ok("rule_level", "lte", 7.5)


def test_integer_fields_are_whole_json_numbers_and_a_boolean_is_never_an_integer() -> None:
    # The form checks Number.isInteger; this pins the server side of the same rule.
    assert autoclose._scalar_ok("dst_port", 443)
    for bad in ("443", 443.0, 443.5, True, None):
        assert not autoclose._scalar_ok("dst_port", bad), bad
    assert autoclose._scalar_ok("identity_privileged", True)
    assert not autoclose._scalar_ok("identity_privileged", 1)
