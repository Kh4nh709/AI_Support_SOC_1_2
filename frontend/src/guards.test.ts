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
const NEEDLES: [string, (text: string) => boolean][] = [
  ["dangerouslySetInnerHTML", (t) => t.includes("dangerouslySetInnerHTML")],
  ["eval(", (t) => EVAL_CALL.test(t)],
  ["new Function", (t) => t.includes("new Function")],
  ["localStorage", (t) => t.includes("localStorage")],
];

it.each(NEEDLES)("no %s in src", (_name, found) => {
  expect(src.filter(([, t]) => found(t)).map(([p]) => p)).toEqual([]);
});
