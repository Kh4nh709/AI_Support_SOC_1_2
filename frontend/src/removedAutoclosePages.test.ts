// src/removedAutoclosePages.test.ts — DEC-214 (P15-T01): the admin console no longer has the pages "Rules tự đóng"
// (`/admin/rules`) and "Digest hằng ngày" (`/admin/digest`). The backend routes behind them stay (auto-close is only
// switched off, DEC-207), so what this file guards is the frontend: no source file of the app names either path, as a
// page or as an API route, and none of the modules that existed only for the two pages is back.
//
// It reads `src` as text. A test file may name the paths (the route test says what happens at them, the e2e run
// refuses a Tier 1 token on the API routes); a source file may not, in code or in a comment.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const SRC = "src";

/** Every `.ts` and `.tsx` file under `src`, relative to the front-end folder. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(ts|tsx)$/.test(name) ? [path] : [];
  });
}

const isTestFile = (path: string): boolean => /\.test\.(ts|tsx)$/.test(path);

describe("the removed auto-close pages (DEC-214)", () => {
  const files = sourceFiles(SRC).filter((path) => !isTestFile(path));

  it("reads the source it checks (a walk that finds nothing would pass for ever)", () => {
    expect(files.length).toBeGreaterThan(80);
    expect(files).toContain(join(SRC, "routes.tsx"));
    expect(files).toContain(join(SRC, "api", "admin.ts"));
    expect(files).toContain(join(SRC, "strings.ts"));
  });

  it.each(["admin/rules", "admin/digest"])(
    "has no non-test source file under src that contains %s, as a page path or as an API path",
    (text) => {
      const found = files.filter((path) => readFileSync(path, "utf8").includes(text));
      expect(found).toEqual([]);
    },
  );

  it("has none of the files that existed only for the two pages", () => {
    const gone = [
      "RulesPage.tsx",
      "RulesPage.test.tsx",
      "RuleCreate.tsx",
      "ruleErrors.ts",
      "ruleFields.ts",
      "ruleFields.test.ts",
      "DigestPage.tsx",
      "DigestPage.test.tsx",
      "digestFigures.ts",
      "digestFigures.test.ts",
    ];
    expect(gone.filter((name) => existsSync(join(SRC, "features", "admin", name)))).toEqual([]);
  });
});
