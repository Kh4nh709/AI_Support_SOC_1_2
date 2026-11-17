// src/features/ti/contrast.test.ts — the colours the page "Threat Intel" puts text and chart marks in, each against the ground it is drawn
// on, from the tokens of src/styles.css: at least 4.5:1 for text (WCAG AA) and 3:1 for a chart's marks (non-text contrast). jsdom computes no
// colour, so axe cannot check this; the pairs are the ones the components use (the sources are read to prove the colour classes are all here).
import { readFileSync, readdirSync } from "node:fs";

const css = readFileSync("src/styles.css", "utf8");
const theme = /@theme\s*\{([^}]*)\}/.exec(css)?.[1] ?? "";
const token = (name: string): string => {
  const hex = new RegExp(`--color-${name}:\\s*(#[0-9a-fA-F]{6});`).exec(theme)?.[1];
  if (hex === undefined) throw new Error(`no token ${name}`);
  return hex;
};

function luminance(hex: string): number {
  const channel = (offset: number) => {
    const c = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function ratio(foreground: string, background: string): number {
  const [light, dark] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return ((light as number) + 0.05) / ((dark as number) + 0.05);
}

it("measures black on white as 21:1 and a grey on its own colour as 1:1 (the measure is the right one)", () => {
  expect(ratio("#000000", "#ffffff")).toBeCloseTo(21, 5);
  expect(ratio("#8593a3", "#8593a3")).toBeCloseTo(1, 5);
});

// [text token, ground token, where the page uses the pair]
const TEXT: [string, string, string][] = [
  ["text", "ground", "the cells, the filters' boxes"],
  [
    "text",
    "surface",
    "the status bar, the KPI numbers, the detail panel, the chart's malware names",
  ],
  ["muted", "ground", "the hints, the notes under the table"],
  [
    "muted",
    "surface",
    "the status bar's labels, the KPI labels, the axis labels, the table header",
  ],
  ["critical", "critical-bg", "the stale banner"],
  ["critical", "ground", "an error line"],
  ["high", "ground", "the line about a failed run"],
  ["high", "high-bg", "the refusal text"],
  ["medium", "ground", "the busy note"],
  ["low", "ground", "the word Đã sao chép"],
];

it.each(TEXT)("%s on %s is at least 4.5:1 (%s)", (text, ground) => {
  expect(ratio(token(text), token(ground))).toBeGreaterThanOrEqual(4.5);
});

// The source colours of the day chart and the bars of the malware chart sit on the card (`bg-surface`).
const MARKS: [string, string][] = [
  ["low", "ThreatFox"],
  ["high", "URLhaus"],
  ["ai-accent", "MalwareBazaar and the malware bars"],
];

it.each(MARKS)("the mark %s (%s) is at least 3:1 on the card", (name) => {
  expect(ratio(token(name), token("surface"))).toBeGreaterThanOrEqual(3);
});

it("gives each source its own colour (the legend names them besides: colour is not the only carrier)", () => {
  expect(new Set(["low", "high", "ai-accent"].map(token)).size).toBe(3);
});

it("uses only text colours of the tokens measured here", () => {
  const dir = "src/features/ti";
  const sources = readdirSync(dir)
    .filter((name) => /\.tsx$/.test(name) && !/\.test\./.test(name) && name !== "testkit.tsx")
    .map((name) => readFileSync(`${dir}/${name}`, "utf8"))
    .join("\n");
  const measured = new Set(TEXT.map(([text]) => text));
  const used = new Set(
    [
      ...sources.matchAll(
        /\b(?:text|fill)-(critical-bg|critical|high-bg|high|medium|low|muted|text|ai-accent)\b/g,
      ),
    ].map((m) => m[1] as string),
  );
  expect(used.size).toBeGreaterThan(3);
  for (const name of used) {
    expect(measured.has(name) || MARKS.some(([mark]) => mark === name), name).toBe(true);
  }
});
