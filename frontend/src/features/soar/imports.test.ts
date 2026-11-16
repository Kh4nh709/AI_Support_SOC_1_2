// src/features/soar/imports.test.ts — what the page "Phản hồi SOAR" pulls out of the console's chunk. The pages of the admin console are
// fetched when their route opens (routesLazy.test.tsx), so the main bundle does not carry them. The SOAR page is in the main bundle
// (it is every role's), so anything it imports from features/admin/ is carried there too, with everything that file imports in turn.
// It once took `visible()` from auditSummary.ts and with it the 42 event builders of the audit page. This reads the imports of the
// non-test source of features/soar/ and of everything it reaches, and holds the reach into features/admin/ to ONE file, the
// shared ConfirmDialog (the repo's own dialog: its focus, Tab and Escape), which needs nothing of the console but the strings.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, normalize } from "node:path";

const SRC = "src";
const SOAR = join(SRC, "features", "soar");
const ADMIN = join(SRC, "features", "admin") + "/";

/** The code of a source with its comments taken out, so a comment that quotes an import is not one. */
const codeOf = (text: string): string =>
  text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

/** The relative modules a source imports (static, `export … from` and dynamic), resolved to the file of the repo they name. */
function importsOf(path: string): string[] {
  const code = codeOf(readFileSync(path, "utf8"));
  const specifiers = [
    // `import type` is erased by the build: it carries no module into a chunk
    ...code.matchAll(/\b(?:import|export)\s+(?!type\b)[^;"']*?\s*from\s*["']([^"']+)["']/g),
    ...code.matchAll(/\bimport\s*\(?\s*["']([^"']+)["']/g),
  ].map((m) => m[1] ?? "");
  const found: string[] = [];
  for (const specifier of specifiers) {
    if (!specifier.startsWith(".")) continue;
    const base = normalize(join(dirname(path), specifier));
    const file = [".ts", ".tsx", "/index.ts", "/index.tsx"]
      .map((ext) => base + ext)
      .find((candidate) => existsSync(candidate));
    if (file !== undefined) found.push(normalize(file));
  }
  return found;
}

const sources = (dir: string): string[] =>
  readdirSync(dir)
    .filter((name) => /\.(ts|tsx)$/.test(name) && !/\.test\./.test(name))
    .map((name) => join(dir, name));

/** Every file reached from `roots` through relative imports, the roots included. */
function reach(roots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const todo = [...roots];
  while (todo.length > 0) {
    const next = todo.pop() as string;
    if (seen.has(next)) continue;
    seen.add(next);
    todo.push(...importsOf(next));
  }
  return seen;
}

describe("the SOAR page and the console's chunk", () => {
  const own = sources(SOAR).filter((path) => !/(testkit|fixtures)\./.test(path));

  it("reads the files of the page (a guard over none would pass for nothing)", () => {
    expect(own.map((path) => path.split("/").at(-1))).toEqual(
      expect.arrayContaining([
        "SoarPage.tsx",
        "DetailPanel.tsx",
        "DecisionDialog.tsx",
        "storage.ts",
      ]),
    );
  });

  it("imports from features/admin/ the shared ConfirmDialog and nothing else", () => {
    const direct = new Set<string>();
    for (const path of own) {
      for (const target of importsOf(path)) if (target.startsWith(ADMIN)) direct.add(target);
    }
    expect([...direct].sort()).toEqual([join(ADMIN, "ConfirmDialog.tsx")]);
  });

  it("reaches no other file of features/admin/ through the files it imports, so the audit page stays in its own chunk", () => {
    const reached = [...reach(own)].filter((path) => path.startsWith(ADMIN)).sort();
    expect(reached).toEqual([join(ADMIN, "ConfirmDialog.tsx")]);
  });

  it("is not imported back by the console (the console is lazy; the page is not)", () => {
    const back = sources(join(SRC, "features", "admin"))
      .filter((path) => importsOf(path).some((target) => target.startsWith(SOAR + "/")))
      .sort();
    expect(back).toEqual([]);
  });

  it("finds an import of the audit summary when there is one (the reader sees what it is meant to see)", () => {
    // the reader on a copy of the text of the page that has the old import: the path it resolves to is the audit module
    const probe = join(SOAR, "DetailPanel.tsx");
    expect(importsOf(probe).length).toBeGreaterThan(3);
    expect(importsOf(join(SRC, "features", "admin", "AuditPage.tsx"))).toContain(
      join(ADMIN, "auditSummary.ts"),
    );
  });
});
