// The chart of IOCs per day, stacked by source: hand-written SVG over `stats.by_day` (already dense, oldest first, `today` last). A bar
// is a column per day, its segments the sources from the baseline up; every height is its count times one scale, so a height IS its
// count. No library, and nothing in it is markup: the labels are text nodes, and the colour of a source is a class chosen from a
// closed table (a source this table lacks is neutral and shown as its code). The colour is never the only carrier: the legend names
// the sources, and every day has a `<title>` that says its counts. Counts are never rounded.
import type { ReactNode } from "react";
import type { TiDay } from "../../api/ti";
import { S, labelOf } from "../../strings";
import { shown } from "./display";

// Whole class names, written out: Tailwind finds a class by reading the source.
const FILL: Record<string, string> = {
  threatfox: "fill-low",
  urlhaus: "fill-high",
  malwarebazaar: "fill-ai-accent",
};
const SWATCH: Record<string, string> = {
  threatfox: "bg-low",
  urlhaus: "bg-high",
  malwarebazaar: "bg-ai-accent",
};
const fillOf = (source: string): string =>
  Object.hasOwn(FILL, source) ? (FILL[source] as string) : "fill-muted";
const swatchOf = (source: string): string =>
  Object.hasOwn(SWATCH, source) ? (SWATCH[source] as string) : "bg-muted";

const WIDTH = 640;
const HEIGHT = 240;
const PAD = { left: 36, right: 8, top: 10, bottom: 26 };
const PLOT_W = WIDTH - PAD.left - PAD.right;
const PLOT_H = HEIGHT - PAD.top - PAD.bottom;
const BASELINE = PAD.top + PLOT_H;
/** A label on the day axis for every fifth day counted back from the last, so `today` always has one. */
const LABEL_EVERY = 5;

/** The count of a source on a day: a whole number from 0, whatever the answer holds. */
function countOf(day: TiDay, source: string): number {
  if (!Object.hasOwn(day, source)) return 0;
  const value = (day as unknown as Record<string, unknown>)[source];
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

function niceStep(raw: number): number {
  const power = 10 ** Math.floor(Math.log10(raw));
  const fraction = raw / power;
  const factor = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  return Math.max(1, factor * power);
}

/** 0 and whole-number ticks up to the first that reaches `max`, at most four steps. */
export function ticksFor(max: number): number[] {
  const step = niceStep(Math.max(max, 1) / 4);
  const ticks = [0];
  for (let tick = step; ; tick += step) {
    ticks.push(tick);
    if (tick >= max) break;
  }
  return ticks;
}

/** `2026-11-17` as `17/11`; a day that is not in that shape is shown as it came. */
export function shortDay(day: string): string {
  const found = /^\d{4}-(\d{2})-(\d{2})$/.exec(day);
  return found === null ? day : `${found[2]}/${found[1]}`;
}

export function DayChart({
  days,
  sources,
}: {
  days: readonly TiDay[];
  sources: readonly string[];
}): ReactNode {
  const total = days.reduce(
    (sum, day) => sum + sources.reduce((inner, source) => inner + countOf(day, source), 0),
    0,
  );
  if (days.length === 0 || total === 0) {
    return <p className="text-sm text-muted">{S.ti.charts.empty}</p>;
  }
  const names = sources.map((source) => shown(labelOf(S.ti.source, source)));
  const peak = Math.max(
    ...days.map((day) => sources.reduce((sum, source) => sum + countOf(day, source), 0)),
  );
  const ticks = ticksFor(peak);
  const top = ticks[ticks.length - 1] as number;
  const scale = PLOT_H / top;
  const slot = PLOT_W / days.length;
  const barWidth = Math.max(2, slot * 0.68);

  return (
    <div className="flex flex-col gap-2">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={S.ti.charts.perDay.aria(days.length, total)}
        className="h-auto w-full"
      >
        {ticks.slice(1).map((tick) => {
          const y = BASELINE - tick * scale;
          return (
            <g key={tick}>
              <line
                data-grid=""
                x1={PAD.left}
                x2={WIDTH - PAD.right}
                y1={y}
                y2={y}
                className="stroke-border"
                strokeWidth={1}
              />
              <text
                data-axis="y"
                x={PAD.left - 6}
                y={y + 3.5}
                textAnchor="end"
                className="fill-muted"
                fontSize={10}
              >
                {tick}
              </text>
            </g>
          );
        })}
        <text
          data-axis="y"
          x={PAD.left - 6}
          y={BASELINE + 3.5}
          textAnchor="end"
          className="fill-muted"
          fontSize={10}
        >
          0
        </text>
        <line
          data-baseline=""
          x1={PAD.left}
          x2={WIDTH - PAD.right}
          y1={BASELINE}
          y2={BASELINE}
          className="stroke-muted"
          strokeWidth={1}
        />
        {days.map((day, index) => {
          const x = PAD.left + index * slot + (slot - barWidth) / 2;
          let stacked = 0;
          const parts: string[] = [];
          const bars: ReactNode[] = [];
          sources.forEach((source, position) => {
            const count = countOf(day, source);
            parts.push(S.ti.charts.perDay.part(names[position] as string, count));
            if (count === 0) return;
            const height = count * scale;
            stacked += height;
            bars.push(
              <rect
                key={source}
                data-source={position}
                data-count={count}
                x={x}
                y={BASELINE - stacked}
                width={barWidth}
                height={height}
                className={fillOf(source)}
              />,
            );
          });
          const empty = stacked === 0;
          const label = shortDay(day.day);
          return (
            <g key={day.day} data-day={day.day}>
              <title>
                {S.ti.charts.perDay.bar(
                  shown(label),
                  empty ? S.ti.charts.perDay.none : parts.join(", "),
                )}
              </title>
              <rect
                x={PAD.left + index * slot}
                y={PAD.top}
                width={slot}
                height={PLOT_H}
                fill="transparent"
              />
              {bars}
              {(days.length - 1 - index) % LABEL_EVERY === 0 && (
                <text
                  data-axis="x"
                  x={x + barWidth / 2}
                  y={BASELINE + 16}
                  textAnchor="middle"
                  className="fill-muted"
                  fontSize={10}
                >
                  {shown(label)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <ul aria-label={S.ti.charts.legend} className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {sources.map((source, position) => (
          <li key={source} className="flex items-center gap-1.5">
            <span
              aria-hidden="true"
              className={`inline-block size-2.5 rounded-sm ${swatchOf(source)}`}
            />
            {names[position]}
          </li>
        ))}
      </ul>
    </div>
  );
}
