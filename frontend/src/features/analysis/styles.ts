// The class strings the analysis panel's pieces share, in the product's own tokens (`styles.css`): the mock-up's inline
// values translated to the utilities the other components use. The panel's artboard puts every card on the page's
// ground (`bg-ground`), a card on the surface, and a quote in a ground-coloured box.

/** The small upper-case caption over a figure or a card: the mock-up's 11 px, 0.06 em letter-spaced muted line. */
export const CAPTION = "text-[11px] uppercase tracking-[0.06em] text-muted";

/** A card of the panel: a surface with a border and a 10 px radius. */
export const CARD = "rounded-[10px] border border-border bg-surface px-4 py-3.5";

/** The focus ring the product's buttons use. */
export const FOCUS =
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text";

/** The colours a tone is drawn in: a three-way scale and the two quiet ones. */
export type Tone = "neutral" | "ai" | "critical" | "high" | "medium" | "low";
