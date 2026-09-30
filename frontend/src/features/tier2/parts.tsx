// The small pieces the three Tier-2 files share: a text made of anything the server sent, the risk-band
// badge, the error notice with its retry, and the class strings of the canvas.
import { S, bandCodeOf, type BandCode } from "../../strings";

export const BUTTON =
  "rounded border border-border bg-surface px-3 py-1 text-sm hover:bg-ground " +
  "focus-visible:outline-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-50";
export const FIELD =
  "w-full rounded border border-border bg-ground px-2 py-1 text-sm focus-visible:outline-2 " +
  "focus-visible:outline-text";
export const PANEL = "rounded border border-border bg-surface p-4";
export const HEADING = "text-xs font-semibold uppercase tracking-wide text-muted";
export const ERROR_TEXT = "text-sm text-critical";

/**
 * Text for a value the server or the model sent: a string as it came, a number or a boolean as
 * its text, nothing as "—", and anything else as JSON. It is rendered as text, never as markup.
 */
export function asText(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value === null || value === undefined) return S.common.missing;
  try {
    return JSON.stringify(value) ?? S.common.missing;
  } catch {
    return S.common.missing;
  }
}

// The colours are keyed by the band code, never by the label: the server's label is read through
// `bandCodeOf` (ruling R8/R13). A label this UI does not know is neutral.
const BAND_STYLE: Record<BandCode | "unknown", string> = {
  critical: "bg-critical-bg text-critical",
  high: "bg-high-bg text-high",
  medium: "bg-medium-bg text-medium",
  low: "bg-low-bg text-low",
  unknown: "border border-border bg-surface text-muted",
};

/** The risk band of a head, by the label the server sent; an unknown label is shown as it came. */
export function BandBadge({ label }: { label: unknown }) {
  const code = bandCodeOf(label);
  const key = code ?? "unknown";
  return (
    <span
      data-band={key}
      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${BAND_STYLE[key]}`}
    >
      {label === null || label === undefined || label === "" ? S.common.missing : asText(label)}
    </span>
  );
}

/** A failed read, and the way to try it again. */
export function ErrorNotice({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center gap-3">
      <p className={ERROR_TEXT}>{message}</p>
      {onRetry !== undefined && (
        <button type="button" onClick={onRetry} className={BUTTON}>
          {S.common.retry}
        </button>
      )}
    </div>
  );
}
