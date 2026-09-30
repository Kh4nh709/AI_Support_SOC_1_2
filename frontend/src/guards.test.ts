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

// Ruling R5: `localStorage` never appears in non-test source, comments included. The token
// lives in memory, sessionStorage and a BroadcastChannel only (spec §3).
it.each(["dangerouslySetInnerHTML", "eval(", "new Function", "localStorage"])(
  "no %s in src",
  (needle) => {
    expect(src.filter(([, t]) => t.includes(needle)).map(([p]) => p)).toEqual([]);
  },
);
