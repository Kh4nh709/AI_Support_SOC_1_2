// The design tokens of the canvas "SOC Console UI" (spec §2), as Tailwind v4 `@theme` variables.
import { readFileSync } from "node:fs";

const css = readFileSync("src/styles.css", "utf8");
const theme = /@theme\s*\{([^}]*)\}/.exec(css)?.[1] ?? "";
const token = (name: string): string | undefined =>
  new RegExp(`--${name}:\\s*([^;]+);`).exec(theme)?.[1]?.trim().toLowerCase();

it("declares a @theme block", () => {
  expect(theme).not.toBe("");
});

it.each([
  ["color-ground", "#0d1117"],
  ["color-surface", "#141a22"],
  ["color-border", "#263241"],
  ["color-text", "#e6ebf1"],
  ["color-muted", "#8593a3"],
  ["color-ai-surface", "#17142a"],
  ["color-ai-border", "#3a3170"],
  ["color-ai-accent", "#a78bfa"],
])("token --%s is %s", (name, value) => {
  expect(token(name)).toBe(value);
});

it.each([
  ["critical", "#fb7185", "#2b0710"],
  ["high", "#fb923c", "#2a1200"],
  ["medium", "#facc15", "#262000"],
  ["low", "#93c5fd", "#0b1e3a"],
])("band %s is %s on %s", (band, fg, bg) => {
  expect(token(`color-${band}`)).toBe(fg);
  expect(token(`color-${band}-bg`)).toBe(bg);
});

it("uses IBM Plex Sans and IBM Plex Mono", () => {
  expect(token("font-sans")).toMatch(/^"ibm plex sans"/);
  expect(token("font-mono")).toMatch(/^"ibm plex mono"/);
});
