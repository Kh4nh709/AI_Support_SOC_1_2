// src/api/adminTypesSource.test.ts — the reader of the backend's Python, on strings written here.
//
// `dictKeys` runs inside adminTypes.test.ts over files that other people edit. Its failure mode has to be a
// throw that names the anchor: a loop that never ends is a `make ui-test` that never ends (a synchronous loop
// is out of reach of Vitest's own timeout), and a quiet wrong answer is a test that passes for nothing.
import { dictKeys, wrapDictLiterals } from "./adminTypesSource";

const RETURN = /return \{/;

describe("dictKeys", () => {
  it("reads the top-level keys and not the nested ones, and a brace inside a string does not count", () => {
    const source = 'return {"a": 1, "b": {"c": 2}, "d": "x: {y}", "e": [{"f": 3}]}';
    expect(dictKeys(source, RETURN)).toEqual(["a", "b", "d", "e"]);
  });

  it("reads a dict that wraps over several lines, and stops at the closing brace", () => {
    const source = 'return {\n    "a": 1,\n    "b": 2,\n}\n\nother = {"z": 0}\n';
    expect(dictKeys(source, RETURN)).toEqual(["a", "b"]);
  });

  it("throws, naming the anchor, when a string has no closing quote", () => {
    const anchor = /return \{(?=\s*"a")/;
    expect(() => dictKeys('return {"a": 1, "b": "never closed}', anchor)).toThrow(
      `unterminated string after: ${String(anchor)}`,
    );
  });

  it("throws on a quote that is not paired, wherever it is in the literal", () => {
    // A single-quoted Python string that holds a double quote: the odd quote opens a string that never closes.
    for (const source of [
      'return {"a": \'say "hi\', "b": 2}',
      'return {"a": 1, "b": {"c": "x}}\n',
      'return {"a": 1,  # say "hi\n "b": 2}',
      'return {"a',
    ]) {
      expect(() => dictKeys(source, RETURN), source).toThrow(/^unterminated string after: /);
    }
  });

  it("skips a quote that a backslash escapes, and still reads the key after it", () => {
    expect(dictKeys('return {"a": "x \\" y", "b": 1}', RETURN)).toEqual(["a", "b"]);
    expect(dictKeys('return {"a": "{\\"}", "b": 1}', RETURN)).toEqual(["a", "b"]);
  });

  it("ends a string at a quote that follows an escaped backslash", () => {
    // `"x\\"` is the string `x\`: the second backslash is the escaped one, and the next quote closes it.
    expect(dictKeys('return {"a": "x\\\\", "b": 1}', RETURN)).toEqual(["a", "b"]);
  });

  it("keeps its other failures: no anchor, an anchor that does not end at a brace, braces that do not balance", () => {
    expect(() => dictKeys('return {"a": 1}', /yield \{/)).toThrow("anchor not found");
    expect(() => dictKeys('return {"a": 1}', /return /)).toThrow("anchor does not end at a brace");
    expect(() => dictKeys('return {"a": {"b": 1}', RETURN)).toThrow("unbalanced braces after");
  });
});

describe("wrapDictLiterals", () => {
  it("puts the brace at the end of its line and each pair on a line of its own, as `ruff format` does", () => {
    expect(wrapDictLiterals('return {"a": 1, "b": {"c": 2}, **rest}')).toBe(
      'return {\n        "a": 1,\n        "b": {\n        "c": 2},\n        **rest}',
    );
  });

  it("puts a dict that is the argument of a call on a line of its own, as `ruff format` does at a short line length", () => {
    const wrapped = wrapDictLiterals('errors.append({"section": s, "error": e})');
    expect(wrapped).toBe('errors.append(\n        {\n        "section": s,\n        "error": e})');
    expect(dictKeys(wrapped, /errors\.append\(\s*\{/)).toEqual(["section", "error"]);
    expect(() => dictKeys(wrapped, /errors\.append\(\{/)).toThrow("anchor not found");
  });

  it("leaves the keys of the literal as they were, so an anchor that survives it reads the same keys", () => {
    const source = 'return {"a": 1, "b": {"c": 2}, "d": [1, 2]}';
    expect(dictKeys(wrapDictLiterals(source), /return \{(?=\s*"a")/)).toEqual(
      dictKeys(source, /return \{/),
    );
  });

  it("is why an anchor with no room after its brace fails: it has to be written `\\{(?=\\s*...)`", () => {
    const source = wrapDictLiterals('return {"min": low, "max": high}');
    expect(() => dictKeys(source, /\{(?="min": low)/)).toThrow("anchor not found");
    expect(dictKeys(source, /\{(?=\s*"min": low)/)).toEqual(["min", "max"]);
  });
});
