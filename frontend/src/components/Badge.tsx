// The small coloured marks of the console: a risk band as a solid badge (the canvas: #FB7185 with dark
// text for "Rất cao"), and a neutral one for anything without a colour of its own.
import type { ReactNode } from "react";
import type { BandCode } from "../api/types";
import { S, bandCodeOfLabel } from "../strings";

// Whole class names, written out: Tailwind finds a class by reading the source, so none is built by parts.
/** The solid badge of a band: the band's colour behind, its dark tone in front. */
export const BAND_SOLID: Record<BandCode, string> = {
  critical: "bg-critical text-critical-bg",
  high: "bg-high text-high-bg",
  medium: "bg-medium text-medium-bg",
  low: "bg-low text-low-bg",
};
/** The outline of a band, for a control that is not pressed: the band's colour on the page's own ground. */
export const BAND_OUTLINE: Record<BandCode, string> = {
  critical: "border-critical text-critical",
  high: "border-high text-high",
  medium: "border-medium text-medium",
  low: "border-low text-low",
};

const BASE = "inline-block rounded px-2 py-0.5 text-xs font-medium whitespace-nowrap";

export function Badge({ band, children }: { band?: BandCode; children: ReactNode }) {
  const tone = band ? BAND_SOLID[band] : "border border-border text-muted";
  return <span className={`${BASE} ${tone}`}>{children}</span>;
}

/**
 * The badge of a row's `risk_band`, which is the server's label (`Rất cao`, `Cao`, `Vừa`, `Thấp`). A label
 * this UI has no colour for is shown as it came, in the neutral badge; no score is a dash.
 */
export function BandBadge({ label }: { label: string | null | undefined }) {
  if (label === null || label === undefined || label === "")
    return <Badge>{S.common.missing}</Badge>;
  const code = bandCodeOfLabel(label);
  return code === null ? <Badge>{label}</Badge> : <Badge band={code}>{label}</Badge>;
}
