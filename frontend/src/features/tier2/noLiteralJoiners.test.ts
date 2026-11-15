// src/features/tier2/noLiteralJoiners.test.ts — a WORDING rule (DEC-221, review of AP-T5): the scorecard's components
// write no word and no joiner of their own that reaches the page. The user-visible separators live in `strings.ts`: the
// ", " between the hosts of a scope is `S.analysis.listSeparator`, the " · " between the parts of one line is
// `S.analysis.separator`, and a labelled line ("a: b") is a function of strings.ts. This reads the sources of the Tier 2
// scorecard and of the shared pieces (not the flat result the admin's draft view draws, which predates the rule) and
// holds them to it. It is not a style rule: a separator that is only whitespace (the space between the classes of a
// class list, or none at all) never reaches the page as a word, and is left alone.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const FILES = [
  ...["ResultPanel", "ResultTabs", "ResultTiles", "runModel", "caseLine"].map((name) =>
    join(
      "src",
      "features",
      "tier2",
      `${name}.${name === "runModel" || name === "caseLine" ? "ts" : "tsx"}`,
    ),
  ),
  ...readdirSync(join("src", "features", "analysis"))
    .filter((name) => /\.(ts|tsx)$/.test(name) && !/\.test\./.test(name))
    .map((name) => join("src", "features", "analysis", name)),
];

/** The code of a file with its comments taken out, so a comment that quotes a joiner is not a joiner. */
function codeOf(path: string): string {
  return readFileSync(path, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

/** The `.join("…")` calls of a piece of code whose separator is written in place and is more than whitespace. */
function wordJoinsIn(code: string): string[] {
  return [...code.matchAll(/\.join\(\s*(["'`])([^"'`]*)\1/g)]
    .filter((found) => (found[2] ?? "").replace(/\\[nrt]/g, " ").trim() !== "")
    .map((found) => `.join(${found[1]}${found[2]}${found[1]})`);
}

it("reads the scorecard's sources (a guard over no files would pass for nothing)", () => {
  expect(FILES.length).toBeGreaterThan(10);
  for (const path of FILES) expect(codeOf(path).length, path).toBeGreaterThan(0);
});

describe("the detector of a joiner that reaches the page", () => {
  it.each([
    ['items.join(", ")', ['.join(", ")']],
    ['parts.join(" · ")', ['.join(" · ")']],
    ["parts.join(' - ')", [".join(' - ')"]],
    ['rows.join("; ")', ['.join("; ")']],
    ['rows.join(",")', ['.join(",")']],
  ])("flags %s", (code, expected) => {
    expect(wordJoinsIn(code)).toEqual(expected);
  });

  it.each([
    '[CARD, "flex gap-2"].join(" ")',
    "classes.filter(Boolean).join(' ')",
    'chars.join("")',
    'lines.join(" \\n")',
    "items.join(S.analysis.listSeparator)",
    "parts.join(S.analysis.separator)",
    "`${a} ${b}`",
  ])("leaves %s alone: whitespace, or a separator that is strings.ts's", (code) => {
    expect(wordJoinsIn(code)).toEqual([]);
  });
});

it("joins no list with a separator written in a component", () => {
  const joins = FILES.flatMap((path) =>
    wordJoinsIn(codeOf(path)).map((found) => `${path}: ${found}`),
  );
  // `.join(S.analysis.listSeparator)` is the way; a quoted ", " or " · " is not
  expect(joins).toEqual([]);
});

it("writes no labelled line of its own: no template that is a value, a colon and another value", () => {
  const lines = FILES.flatMap((path) =>
    [...codeOf(path).matchAll(/`[^`]*\}: \$\{[^`]*`/g)].map((found) => `${path}: ${found[0]}`),
  );
  expect(lines).toEqual([]);
});

it("writes no middle dot or comma between two parts of a line", () => {
  const dots = FILES.flatMap((path) =>
    [...codeOf(path).matchAll(/["'`]\s*·\s*["'`]|\}\s·\s\$\{|\}, \$\{/g)].map(
      (found) => `${path}: ${found[0]}`,
    ),
  );
  expect(dots).toEqual([]);
});
