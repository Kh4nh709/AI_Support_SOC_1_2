// The mark beside a line of the panel: a check (pass or verified), a warning triangle, or a dash (does not apply). An
// inline stroke SVG, as the mock-up draws them, never an emoji. With a label it is an image a screen reader speaks;
// without one it is decoration, and the text beside it says the same thing.
//
// The Tier 1 panel's highlights add two arrows (AP-T4): `up` (towards an attack, in the high-severity orange) and `down`
// (towards a benign reading, in the calm blue). The three marks of the Tier 2 panel are as they were.

export type StatusKind = "pass" | "warn" | "na" | "up" | "down";

const PATH: Record<StatusKind, string> = {
  pass: "M20 6 9 17l-5-5",
  warn: "M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  na: "M5 12h14",
  up: "M12 5v14M5 12l7-7 7 7",
  down: "M12 19V5M5 12l7 7 7-7",
};

const STROKE: Record<StatusKind, string> = {
  pass: "stroke-ok",
  warn: "stroke-medium",
  na: "stroke-muted",
  up: "stroke-high",
  down: "stroke-low",
};

export function StatusIcon({ kind, label }: { kind: StatusKind; label?: string }) {
  const spoken =
    label === undefined ? { "aria-hidden": true } : { role: "img", "aria-label": label };
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      data-kind={kind}
      className={`mt-0.5 shrink-0 ${STROKE[kind]}`}
      {...spoken}
    >
      <path d={PATH[kind]} />
    </svg>
  );
}
