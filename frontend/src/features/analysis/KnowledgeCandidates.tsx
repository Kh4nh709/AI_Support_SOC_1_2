// The approved knowledge entries a lookup scored, best first: the percentage, the entry's title and the label of the
// conclusion it was learned from, and under them the bar the mock-up draws. The bar is an SVG, not an inline style: the
// product's CSP allows no style attribute. A title or a conclusion the server could not read is left out or named as
// missing; a conclusion this page has no words for is shown as it came.
import { S, labelOf } from "../../strings";
import type { Tone } from "./styles";

export type CandidateRow = { pct: number; title: string | null; conclusion: string | null };

/** The tone of a conclusion's label: a real incident warns, a violation is a caution, a closed false positive is calm. */
const CONCLUSION_TONE: Record<string, Tone> = {
  confirmed_incident: "high",
  concluded_policy_violation: "medium",
  concluded_fp: "low",
  closed_fp: "low",
  closed_benign: "low",
};

const TONE_INK: Record<Tone | "muted", string> = {
  neutral: "text-text",
  ai: "text-text",
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  muted: "text-muted",
};

export function KnowledgeCandidates({
  rows,
  bar = true,
}: {
  rows: readonly CandidateRow[];
  /** The mock-up of the alert page draws a bar under each title; the case page's does not. */
  bar?: boolean;
}) {
  return (
    <ul className="grid grid-cols-[44px_1fr] items-center gap-x-2.5 gap-y-2.5 text-[13px]">
      {rows.map((row, index) => {
        const tone =
          row.conclusion !== null && Object.hasOwn(CONCLUSION_TONE, row.conclusion)
            ? (CONCLUSION_TONE[row.conclusion] ?? "muted")
            : "muted";
        return (
          <li key={index} className="col-span-2 grid grid-cols-subgrid items-center">
            <span className="font-mono">{`${row.pct}%`}</span>
            <div className="flex min-w-0 flex-col gap-1">
              {bar && (
                <svg aria-hidden="true" className="h-1.5 w-full" preserveAspectRatio="none">
                  <rect width="100%" height="100%" rx="3" className="fill-border" />
                  <rect
                    data-bar-fill
                    width={`${row.pct}%`}
                    height="100%"
                    rx="3"
                    className="fill-muted"
                  />
                </svg>
              )}
              <div className="text-xs break-words text-text">
                {row.title ?? S.analysis.knowledge.untitled}
                {row.conclusion !== null && (
                  <>
                    {" · "}
                    <span data-tone={tone} className={TONE_INK[tone]}>
                      {labelOf(S.analysis.knowledge.conclusion, row.conclusion)}
                    </span>
                  </>
                )}
              </div>
            </div>
          </li>
        );
      })}
    </ul>
  );
}
