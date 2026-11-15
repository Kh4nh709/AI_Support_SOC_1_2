// One of the four score tiles above the tabs: a caption, a value and one line under it. The tone is the tile's colour:
// the conclusion's own, the violet of the confidence tile, or the neutral surface. A tile that has its own content
// (the confidence meter) passes it as children, in place of the value and the note.
import type { ReactNode } from "react";
import { useId } from "react";
import { CAPTION_BASE, type Tone } from "./styles";

const FRAME: Record<Tone, string> = {
  neutral: "border-border bg-surface",
  ai: "border-ai-border bg-ai-surface",
  critical: "border-critical bg-critical-bg",
  high: "border-high bg-high-bg",
  medium: "border-medium bg-medium-bg",
  low: "border-low bg-low-bg",
};

// A coloured tile writes all of its text in its own colour; a quiet one writes the value in the text colour.
const INK: Record<Tone, string> = {
  neutral: "text-text",
  ai: "text-text",
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

const CAPTION_INK: Record<Tone, string> = {
  neutral: "text-muted",
  ai: "text-muted",
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

export type NoteTone = "muted" | "warn";

export function ScoreTile({
  label,
  tone = "neutral",
  value,
  figure = false,
  note,
  noteTone = "muted",
  children,
}: {
  label: string;
  tone?: Tone;
  value?: ReactNode;
  /** A short number or ratio: the mock-up's 28 px monospace. Otherwise the value is a word, smaller and wrapping. */
  figure?: boolean;
  note?: ReactNode;
  noteTone?: NoteTone;
  children?: ReactNode;
}) {
  const labelId = useId();
  const coloured = tone !== "neutral" && tone !== "ai";
  return (
    <div
      role="group"
      aria-labelledby={labelId}
      data-tone={tone}
      className={`flex min-w-0 flex-col gap-0.5 rounded-[10px] border p-3 ${FRAME[tone]}`}
    >
      <span
        id={labelId}
        className={`${CAPTION_BASE} ${coloured ? CAPTION_INK[tone] : "text-muted"}`}
      >
        {label}
      </span>
      {children !== undefined ? (
        children
      ) : (
        <>
          <span
            className={
              figure
                ? `font-mono text-[28px] leading-8 font-semibold ${INK[tone]}`
                : `text-base leading-6 font-semibold break-words ${INK[tone]}`
            }
          >
            {value}
          </span>
          {note !== undefined && note !== null && (
            <span
              data-tone={noteTone}
              className={`text-xs ${
                noteTone === "warn" ? "text-medium" : coloured ? INK[tone] : "text-muted"
              }`}
            >
              {note}
            </span>
          )}
        </>
      )}
    </div>
  );
}
