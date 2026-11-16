// src/features/soar/contrast.test.ts — the colours the page "Phản hồi SOAR" puts text in, each against the ground it is
// drawn on, from the tokens of src/styles.css: at least 4.5:1 (WCAG AA for text). jsdom computes no colour, so axe cannot
// check this; the pairs are the ones the components use (a class name here is a class name there: the sources are read
// to prove it).
import { readFileSync } from "node:fs";

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

export function ratio(foreground: string, background: string): number {
  const [light, dark] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return ((light as number) + 0.05) / ((dark as number) + 0.05);
}

describe("the contrast of the page's colours", () => {
  it("measures black on white as 21:1 and a grey on its own colour as 1:1 (the measure is the right one)", () => {
    expect(ratio("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(ratio("#8593a3", "#8593a3")).toBeCloseTo(1, 5);
  });

  // [text token, ground token, where the page uses the pair]
  const PAIRS: [string, string, string][] = [
    ["text", "ground", "body text, the cells"],
    ["text", "surface", "the header of the table, a notice's title"],
    ["muted", "ground", "hints, the empty line, the countdown"],
    ["muted", "surface", "the table header, the grey info notice"],
    ["critical", "ground", "a score from 70, an error line, the word Lỗi"],
    ["high", "ground", "a score from 40, a reminder that is due"],
    ["medium", "ground", "a score below 40"],
    ["low", "ground", "a note about what happened"],
    [
      "text",
      "critical-bg",
      "the title and note of an error notice, the strong warning of the dialog",
    ],
    ["text", "high-bg", "the title and note of a warning notice"],
    ["critical", "critical-bg", "an error notice"],
    ["high", "high-bg", "a warning notice"],
    ["critical-bg", "critical", "the count in the header's link"],
    ["critical", "surface", "an error line on a hovered row"],
    ["high", "surface", "a score on a hovered row"],
    ["medium", "surface", "a score on a hovered row"],
  ];

  it.each(PAIRS)("%s on %s is at least 4.5:1 (%s)", (text, ground) => {
    expect(ratio(token(text), token(ground))).toBeGreaterThanOrEqual(4.5);
  });

  it("muted text on the ground of the shared dialog (a literal of ConfirmDialog, not a token) is at least 4.5:1: the hint of a shut confirm and the tag of a button", () => {
    expect(ratio(token("muted"), "#18202a")).toBeGreaterThanOrEqual(4.5);
    expect(ratio(token("text"), "#18202a")).toBeGreaterThanOrEqual(4.5);
  });

  it("uses only pairs that are in this list: a colour class of the page is a token this file measures", () => {
    const sources = [
      "SoarPage.tsx",
      "RowActions.tsx",
      "Notices.tsx",
      "Timers.tsx",
      "DetailPanel.tsx",
      "SignalSwitch.tsx",
      "SoarTable.tsx",
      "DecisionDialog.tsx",
      "model.ts",
      "SoarNavBadge.tsx",
    ]
      .map((name) => {
        try {
          return readFileSync(`src/features/soar/${name}`, "utf8");
        } catch {
          return "";
        }
      })
      .join("\n");
    const used = new Set(
      [...sources.matchAll(/\btext-(critical-bg|critical|high|medium|low|muted|text)\b/g)].map(
        (m) => m[1],
      ),
    );
    expect(used.size).toBeGreaterThan(3);
    const measured = new Set(PAIRS.map(([text]) => text));
    for (const name of used) expect(measured.has(name as string), name).toBe(true);
    // no colour is written as a literal: the page speaks in tokens
    expect(sources).not.toMatch(/\b(?:text|bg|border)-\[#/);
  });
});
