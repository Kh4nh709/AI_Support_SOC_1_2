// src/guards.test.ts — the security guards of the spec §6
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
const files = (d: string): string[] =>
  readdirSync(d).flatMap((f) => {
    const p = join(d, f);
    return statSync(p).isDirectory()
      ? files(p)
      : /\.(ts|tsx)$/.test(p) && !/\.test\./.test(p)
        ? [p]
        : [];
  });
const src = files("src").map((p) => [p, readFileSync(p, "utf8")] as const);

it("scans the non-test source (a guard over no files would pass for nothing)", () => {
  const scanned = src.map(([p]) => p);
  expect(scanned).toContain(join("src", "app.tsx"));
  expect(scanned).toContain(join("src", "format.ts"));
  expect(scanned).toContain(join("src", "strings.ts"));
  expect(scanned.some((p) => /\.test\./.test(p))).toBe(false);
});

it("scans the admin console too, so its zero count of dangerouslySetInnerHTML is a count and not a gap", () => {
  const scanned = src.map(([p]) => p);
  for (const name of ["AdminLayout.tsx", "ConfirmDialog.tsx", "adminKeys.ts", "UsersPage.tsx"]) {
    expect(scanned).toContain(join("src", "features", "admin", name));
  }
  expect(scanned).toContain(join("src", "api", "admin.ts"));
});

// A call of `eval`, not any identifier that ends in it: `retrieval(` is not a call of eval.
const EVAL_CALL = /\beval\s*\(/;

it("matches a call of eval and nothing that merely ends in it", () => {
  for (const call of ["eval(x)", "eval (x)", "window.eval('1')", "x = eval(\n)"]) {
    expect(EVAL_CALL.test(call), call).toBe(true);
  }
  for (const other of ["retrieval(x)", "medieval(1)", "my_eval(x)", "evaluate(x)", "evalue"]) {
    expect(EVAL_CALL.test(other), other).toBe(false);
  }
});

// Ruling R5: `localStorage` never appears in non-test source, comments included. The token
// lives in memory, sessionStorage and a BroadcastChannel only (spec §3).
//
// One file is let through, by its exact path (SR-T2, the Owner's own list for the page "Phản hồi SOAR": the new-ticket
// signal's switch and the dismissed notices "live in localStorage"). It holds two non-secret preferences and nothing of
// the session; the tests below read it to prove that, and prove no other file of src/ is let through.
const LOCAL_STORAGE_HOME = join("src", "features", "soar", "storage.ts");
const NEEDLES: [string, (text: string) => boolean][] = [
  ["dangerouslySetInnerHTML", (t) => t.includes("dangerouslySetInnerHTML")],
  ["eval(", (t) => EVAL_CALL.test(t)],
  ["new Function", (t) => t.includes("new Function")],
  ["localStorage", (t) => t.includes("localStorage")],
  // P11-T10: the admin console is in the app; no link leaves for the API port (the old Jinja console).
  [":8000", (t) => t.includes(":8000")],
  ["adminLegacy", (t) => t.includes("adminLegacy")],
];

it.each(NEEDLES)("no %s in src", (name, found) => {
  expect(
    src
      .filter(([p, t]) => found(t) && !(name === "localStorage" && p === LOCAL_STORAGE_HOME))
      .map(([p]) => p),
  ).toEqual([]);
});

describe("the one file that may name localStorage", () => {
  const home = src.find(([p]) => p === LOCAL_STORAGE_HOME)?.[1] ?? "";
  /** The code of the file with its comments taken out, so a comment that quotes a word is not a use of it. */
  const code = home.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

  it("is scanned, and is the only source file that names it", () => {
    expect(home).not.toBe("");
    expect(src.filter(([, t]) => t.includes("localStorage")).map(([p]) => p)).toEqual([
      LOCAL_STORAGE_HOME,
    ]);
  });

  it("writes only the two keys of the SOAR page, and nothing that is a token or a session", () => {
    expect(
      [...code.matchAll(/localStorage\.(?:set|remove)Item\(\s*([A-Z_]+)/g)].map((m) => m[1]).sort(),
    ).toEqual(["DISMISSED_KEY", "SIGNAL_KEY"]);
    expect(code).toContain('SIGNAL_KEY = "soc.soar.signal"');
    expect(code).toContain('DISMISSED_KEY = "soc.soar.dismissed"');
    expect(code).not.toMatch(/token|session|password|auth/i);
    expect(code).not.toMatch(/^import\b/m);
  });

  it("is not imported by the session, the auth code or the API client", () => {
    const owners = src.filter(([p]) => /^src[\\/](auth|api)[\\/]/.test(p));
    expect(owners.length).toBeGreaterThan(5);
    expect(owners.filter(([, t]) => /features[\\/]soar|soar[\\/]storage/.test(t))).toEqual([]);
  });
});

// P10-T13 deleted the Jinja pages. A comment that still cites one of their modules points a reader at a
// file that is not there; the words they carried are the UI's own now (`strings.ts`), and the tables the
// UI follows have their homes in `backend/app/tier1` and `backend/app/tier2`.
const DELETED_MODULES = ["alerts_pages", "cases_pages", "case_analyze_pages"];

it.each(DELETED_MODULES)("cites no %s, a Jinja module that no longer exists", (name) => {
  expect(src.filter(([, t]) => t.includes(name)).map(([p]) => p)).toEqual([]);
});
