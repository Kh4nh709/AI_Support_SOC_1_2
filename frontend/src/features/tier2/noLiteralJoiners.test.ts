// src/features/tier2/noLiteralJoiners.test.ts — the scorecard's components write no word and no joiner of their own
// (strings.ts's rule, DEC-221, review of AP-T5): the ", " between the hosts of a scope, the ": " of a labelled line and
// the " · " between the parts of one are `S.analysis.listSeparator`, `S.analysis.separator` and a function of strings.ts.
// This reads the sources of the Tier 2 scorecard and of the shared pieces (not the flat result the admin's draft view
// draws, which predates the rule) and holds them to it.
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

it("reads the scorecard's sources (a guard over no files would pass for nothing)", () => {
  expect(FILES.length).toBeGreaterThan(10);
  for (const path of FILES) expect(codeOf(path).length, path).toBeGreaterThan(0);
});

it("joins no list with a separator written in a component", () => {
  const joins = FILES.flatMap((path) =>
    [...codeOf(path).matchAll(/\.join\(\s*(["'`][^"'`]*["'`])/g)].map(
      (found) => `${path}: .join(${found[1]})`,
    ),
  );
  // `.join(S.analysis.separator)` is the way; a quoted separator, even "" , is not
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
