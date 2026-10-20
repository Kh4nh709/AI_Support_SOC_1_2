// src/api/adminTypesSource.ts — the reader of the backend's Python that adminTypes.test.ts compares the types with.
//
// It is a module of its own so that it has tests of its own (adminTypesSource.test.ts): a reader that a test
// trusts has to be tested, or its failure mode is a test that hangs or that passes for nothing. Nothing in the app
// imports it, and it touches no file: the caller reads the source and passes the text.

/**
 * The text laid out as `ruff format` lays out a dict literal that no longer fits on one line: the `{` ends its
 * line (and, for the argument of a call, starts one: `f(` then `{`), and each pair has a line of its own. Only the
 * white space changes. adminTypes.test.ts reads the backend
 * through this as well, so an anchor that is written for today's one-line layout fails there, before a wrap does.
 */
export function wrapDictLiterals(source: string): string {
  return source
    .replace(/\((?=\s*\{)/g, "(\n        ")
    .replace(/\{(?=\s*(?:"|\*\*))/g, "{\n        ")
    .replace(/,[ \t]+(?="|\*\*)/g, ",\n        ");
}

/** The index of the `quote` that closes the string whose first character is at `from`, or -1. A backslash skips the next character. */
function closingQuote(source: string, from: number, quote: string): number {
  for (let i = from; i < source.length; i += 1) {
    const ch = source.charAt(i);
    if (ch === "\\") i += 1;
    else if (ch === quote) return i;
  }
  return -1;
}

/** A colon after any white space, read where `lastIndex` is (it is sticky): what follows the closing quote of a key. */
const COLON = /\s*:/y;

/**
 * The string keys of the dict literal whose `{` ends the match of `anchor`, at its top level: `"key":`.
 * Strings, in double or single quotes, are skipped whole, so a brace or a quote in one does not count, and so is a
 * quote escaped inside one; a `#` comment is skipped to the end of its line. It throws, and never loops, when the
 * anchor is not found or does not end at a brace, when a string has no closing quote, or when the braces do not balance.
 *
 * Known limits, because the backend's dicts do not need more: a triple-quoted string is read as three strings in a
 * row (harmless for an empty or a plain one, wrong for one that holds a quote), a raw string that ends in a backslash
 * is read as if the backslash escaped its quote, and only a key in double quotes is a key (ruff writes them so).
 */
export function dictKeys(source: string, anchor: RegExp): string[] {
  const m = anchor.exec(source);
  if (m === null) throw new Error(`anchor not found: ${String(anchor)}`);
  const open = m.index + m[0].length - 1;
  if (source[open] !== "{") throw new Error(`anchor does not end at a brace: ${String(anchor)}`);
  const keys: string[] = [];
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    const ch = source.charAt(i);
    if (ch === '"' || ch === "'") {
      const end = closingQuote(source, i + 1, ch);
      // No closing quote: `end` would be -1, `i = end` would send the scan back to the start of the text, and it
      // would never leave it.
      if (end === -1) throw new Error(`unterminated string after: ${String(anchor)}`);
      COLON.lastIndex = end + 1;
      if (ch === '"' && depth === 1 && COLON.test(source)) keys.push(source.slice(i + 1, end));
      i = end;
    } else if (ch === "#") {
      const eol = source.indexOf("\n", i);
      i = eol === -1 ? source.length : eol;
    } else if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return keys;
    }
  }
  throw new Error(`unbalanced braces after: ${String(anchor)}`);
}
