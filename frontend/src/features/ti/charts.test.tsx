// src/features/ti/charts.test.tsx — the two charts, hand-written SVG: they draw from the stats (heights and widths are the counts, to a
// common scale), a name from the feed is text in the SVG and never markup, and there is no chart library to lean on.
import { render, screen, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import type { TiDay } from "../../api/ti";
import { S } from "../../strings";
import { DayChart } from "./DayChart";
import { tiFixture } from "./fixtures";
import { MalwareChart } from "./MalwareChart";

const SOURCES = ["threatfox", "urlhaus", "malwarebazaar"] as const;

const day = (d: string, threatfox: number, urlhaus: number, malwarebazaar: number): TiDay => ({
  day: d,
  threatfox,
  urlhaus,
  malwarebazaar,
  total: threatfox + urlhaus + malwarebazaar,
});

const rectsOf = (svg: Element) => [...svg.querySelectorAll("rect[data-source]")];
const num = (el: Element, name: string): number => Number(el.getAttribute(name));

describe("DayChart", () => {
  const series = [
    day("2026-11-13", 4, 0, 2),
    day("2026-11-14", 0, 0, 0),
    day("2026-11-15", 8, 2, 0),
    day("2026-11-16", 1, 1, 1),
    day("2026-11-17", 0, 5, 3),
  ];

  const chart = () => {
    render(<DayChart days={series} sources={[...SOURCES]} />);
    return screen.getByRole("img", { name: S.ti.charts.perDay.aria(5, 27) });
  };

  it("is an SVG with a text label that says what it shows and the total", () => {
    const svg = chart();
    expect(svg.tagName.toLowerCase()).toBe("svg");
    expect(svg).toHaveAttribute("viewBox");
  });

  it("draws one rectangle per non-zero count, and none for a day with no IOC", () => {
    const svg = chart();
    const rects = rectsOf(svg);
    expect(rects).toHaveLength(2 + 0 + 2 + 3 + 2);
    const nonZeroPerDay = Object.fromEntries(
      series.map((d) => [d.day, SOURCES.filter((s) => d[s] > 0).length]),
    );
    for (const [dayName, count] of Object.entries(nonZeroPerDay)) {
      const group = svg.querySelector(`g[data-day="${dayName}"]`);
      expect(group, dayName).not.toBeNull();
      expect(group?.querySelectorAll("rect[data-source]")).toHaveLength(count);
    }
  });

  it("scales every height by the same factor, so a height is its count", () => {
    const rects = rectsOf(chart());
    const scale = num(rects[0] as Element, "height") / num(rects[0] as Element, "data-count");
    expect(scale).toBeGreaterThan(0);
    for (const rect of rects) {
      expect(num(rect, "height") / num(rect, "data-count")).toBeCloseTo(scale, 6);
    }
  });

  it("stacks the sources of a day one on the other, from the baseline up, with no gap", () => {
    const svg = chart();
    const baseline = num(svg.querySelector("line[data-baseline]") as Element, "y1");
    for (const d of series) {
      const parts = [
        ...(svg.querySelector(`g[data-day="${d.day}"]`)?.querySelectorAll("rect[data-source]") ??
          []),
      ];
      if (parts.length === 0) continue;
      let top = baseline;
      for (const rect of parts) {
        expect(num(rect, "y") + num(rect, "height")).toBeCloseTo(top, 6);
        top = num(rect, "y");
      }
    }
  });

  it("keeps the tallest stack inside the plot, and the top gridline is at or above it", () => {
    const svg = chart();
    const tops = rectsOf(svg).map((rect) => num(rect, "y"));
    const gridTop = Math.min(
      ...[...svg.querySelectorAll("line[data-grid]")].map((l) => num(l, "y1")),
    );
    expect(Math.min(...tops)).toBeGreaterThanOrEqual(gridTop - 1e-6);
  });

  it("draws from the stats: other counts, other heights, to the scale of the biggest stack", () => {
    const heights = (counts: number[]) => {
      const view = render(
        <DayChart
          days={counts.map((n, i) => day(`2026-11-1${i + 1}`, n, 0, 0))}
          sources={[...SOURCES]}
        />,
      );
      const found = rectsOf(view.container).map((rect) => num(rect, "height"));
      view.unmount();
      return found;
    };
    const [tall, half] = heights([10, 5]) as [number, number];
    expect(half * 2).toBeCloseTo(tall, 6);
    const [big, small] = heights([10, 2]) as [number, number];
    expect(small * 5).toBeCloseTo(big, 6);
  });

  it("names each day for a pointer and a screen reader: the day and the count of each source", () => {
    const svg = chart();
    const group = svg.querySelector('g[data-day="2026-11-15"]') as Element;
    expect(group.querySelector("title")?.textContent).toBe(
      S.ti.charts.perDay.bar(
        "15/11",
        [
          S.ti.charts.perDay.part(S.ti.source.threatfox, 8),
          S.ti.charts.perDay.part(S.ti.source.urlhaus, 2),
          S.ti.charts.perDay.part(S.ti.source.malwarebazaar, 0),
        ].join(", "),
      ),
    );
    const empty = svg.querySelector('g[data-day="2026-11-14"] title')?.textContent;
    expect(empty).toBe(S.ti.charts.perDay.bar("14/11", S.ti.charts.perDay.none));
  });

  it("labels the axis with days as dd/mm, the last day included, and counts on the left", () => {
    const svg = chart();
    const labels = [...svg.querySelectorAll("text[data-axis='x']")].map((t) => t.textContent);
    expect(labels).toContain("17/11");
    const ticks = [...svg.querySelectorAll("text[data-axis='y']")].map((t) => t.textContent);
    expect(ticks).toContain("0");
    expect(ticks.length).toBeGreaterThanOrEqual(3);
  });

  it("has a legend with the three sources by name (colour is never the only carrier)", () => {
    render(<DayChart days={series} sources={[...SOURCES]} />);
    const legend = screen.getByRole("list", { name: S.ti.charts.legend });
    expect(
      within(legend)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([S.ti.source.threatfox, S.ti.source.urlhaus, S.ti.source.malwarebazaar]);
  });

  it("says there is nothing to draw when every day is zero, and draws no rectangle", () => {
    const view = render(
      <DayChart
        days={[day("2026-11-16", 0, 0, 0), day("2026-11-17", 0, 0, 0)]}
        sources={[...SOURCES]}
      />,
    );
    expect(screen.getByText(S.ti.charts.empty)).toBeInTheDocument();
    expect(rectsOf(view.container)).toHaveLength(0);
  });

  it("draws the full 30-day fixture without a rectangle outside the plot", () => {
    const view = render(<DayChart days={tiFixture.days()} sources={[...SOURCES]} />);
    const svg = view.container.querySelector("svg") as SVGElement;
    const [, , width, height] = (svg.getAttribute("viewBox") ?? "").split(" ").map(Number);
    for (const rect of rectsOf(svg)) {
      expect(num(rect, "x")).toBeGreaterThanOrEqual(0);
      expect(num(rect, "x") + num(rect, "width")).toBeLessThanOrEqual(width as number);
      expect(num(rect, "y")).toBeGreaterThanOrEqual(0);
      expect(num(rect, "y") + num(rect, "height")).toBeLessThanOrEqual(height as number);
    }
    expect(svg.querySelectorAll("g[data-day]")).toHaveLength(30);
  });

  it("shows an unknown source in a neutral colour and as its code, and does not crash", () => {
    const odd = [{ ...day("2026-11-17", 1, 0, 0), other: 3, total: 4 }] as unknown as TiDay[];
    render(<DayChart days={odd} sources={["threatfox", "other" as never]} />);
    expect(screen.getByRole("list", { name: S.ti.charts.legend })).toHaveTextContent("other");
  });
});

describe("MalwareChart", () => {
  const items = [
    { malware: "Example.Rat", count: 40 },
    { malware: "Example.Loader", count: 20 },
    { malware: "Example.Dropper", count: 10 },
  ];

  it("is an SVG with a label, one row per malware, in the order served", () => {
    const view = render(<MalwareChart items={items} />);
    const svg = screen.getByRole("img", { name: S.ti.charts.topMalware.aria(3) });
    expect(svg.tagName.toLowerCase()).toBe("svg");
    const rows = [...view.container.querySelectorAll("g[data-row]")];
    expect(rows.map((r) => r.querySelector("text[data-name]")?.textContent)).toEqual([
      "Example.Rat",
      "Example.Loader",
      "Example.Dropper",
    ]);
  });

  it("draws a bar as wide as its count, to a common scale, the biggest at the full length", () => {
    const view = render(<MalwareChart items={items} />);
    const bars = [...view.container.querySelectorAll("rect[data-count]")];
    const widths = bars.map((bar) => num(bar, "width"));
    expect(widths[0]).toBeGreaterThan(0);
    expect(widths[1]).toBeCloseTo((widths[0] as number) / 2, 6);
    expect(widths[2]).toBeCloseTo((widths[0] as number) / 4, 6);
  });

  it("prints the count at the end of the bar", () => {
    const view = render(<MalwareChart items={items} />);
    expect(
      [...view.container.querySelectorAll("text[data-value]")].map((t) => t.textContent),
    ).toEqual(["40", "20", "10"]);
  });

  it("names each row for a pointer: the full name and the count", () => {
    const view = render(<MalwareChart items={items} />);
    expect(view.container.querySelector("g[data-row] title")?.textContent).toBe(
      S.ti.charts.topMalware.bar("Example.Rat", 40),
    );
  });

  it("is text for a hostile name: no element is made of it, a long one is cut with the whole name in the title", () => {
    const hostile = "<img src=x onerror=1>";
    const long = `Long${"x".repeat(200)}`;
    const view = render(
      <MalwareChart
        items={[
          { malware: hostile, count: 3 },
          { malware: long, count: 2 },
        ]}
      />,
    );
    expect(view.container.querySelector("img")).toBeNull();
    const names = [...view.container.querySelectorAll("text[data-name]")].map((t) => t.textContent);
    expect(names[0]).toBe(hostile);
    expect((names[1] as string).length).toBeLessThan(long.length);
    expect(names[1]).toMatch(/…$/);
    const titles = [...view.container.querySelectorAll("g[data-row] title")].map(
      (t) => t.textContent,
    );
    expect(titles[1]).toContain(long);
  });

  it("shows a bidirectional override and a zero-width space as visible escapes, never as the characters", () => {
    const view = render(<MalwareChart items={[{ malware: "Ex\u202eRat\u200b", count: 1 }]} />);
    const name = view.container.querySelector("text[data-name]")?.textContent ?? "";
    expect(name).toBe("Ex\\u202eRat\\u200b");
    expect(view.container.textContent).not.toMatch(/[\u202e\u200b]/);
  });

  it("says there is nothing to draw for no malware", () => {
    render(<MalwareChart items={[]} />);
    expect(screen.getByText(S.ti.charts.empty)).toBeInTheDocument();
  });
});

describe("no chart library", () => {
  it("is in no dependency of the app", () => {
    const pkg = JSON.parse(readFileSync("package.json", "utf8")) as {
      dependencies: Record<string, string>;
    };
    expect(Object.keys(pkg.dependencies).sort()).toEqual([
      "@fontsource/ibm-plex-mono",
      "@fontsource/ibm-plex-sans",
      "@tanstack/react-query",
      "react",
      "react-dom",
      "react-router",
    ]);
  });
});
