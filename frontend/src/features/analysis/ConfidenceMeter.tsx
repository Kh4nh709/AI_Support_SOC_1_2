// The body of the confidence tile: the word, and three segments filled for low (1), medium (2) or high (3). A level
// the page has no scale for is shown as its word alone, with no meter, so nothing is claimed that was not said.
import { S } from "../../strings";

const FILLED = { low: 1, medium: 2, high: 3 } as const;

export type MeterLevel = keyof typeof FILLED;

export function ConfidenceMeter({ level, word }: { level: MeterLevel | null; word: string }) {
  const filled = level === null ? 0 : FILLED[level];
  return (
    <>
      <span className="text-base leading-6 font-semibold break-words">{word}</span>
      {level !== null && (
        <span role="img" aria-label={S.analysis.meter(filled)} className="mt-1 flex gap-[3px]">
          {[1, 2, 3].map((segment) => (
            <span
              key={segment}
              data-filled={segment <= filled}
              className={`h-1.5 w-[22px] rounded-[3px] ${segment <= filled ? "bg-ai-accent" : "bg-ai-border"}`}
            />
          ))}
        </span>
      )}
    </>
  );
}
