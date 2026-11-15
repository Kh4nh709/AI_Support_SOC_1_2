// The cards a tab is made of: a titled card, the "label over value" grid, the label/value rows of the technical tab,
// and a line of text with a mark beside it. Plain structure: the words come from the caller.
import { useId, type ReactNode } from "react";
import { StatusIcon, type StatusKind } from "./StatusIcon";
import { CAPTION, CARD } from "./styles";

/** A card with a title, and whatever the caller wants beside it ("23 mục được chấm điểm"). */
export function Card({
  title,
  aside,
  variant = "caption",
  children,
}: {
  title?: string;
  aside?: ReactNode;
  /** `caption` is the small upper-case title of the overview's cards; `title` the semibold one of the lists. */
  variant?: "caption" | "title";
  children: ReactNode;
}) {
  const titleId = useId();
  if (title === undefined) return <div className={`${CARD} flex flex-col gap-2`}>{children}</div>;
  return (
    <section aria-labelledby={titleId} className={`${CARD} flex flex-col gap-2`}>
      <div className="flex items-baseline justify-between gap-3">
        <h3 id={titleId} className={variant === "caption" ? CAPTION : "text-sm font-semibold"}>
          {title}
        </h3>
        {aside !== undefined && aside !== null && (
          <span className="shrink-0 text-xs text-muted">{aside}</span>
        )}
      </div>
      {children}
    </section>
  );
}

/** A grid of label over value over note, three to a row: the scope of a case, the facts of an alert. */
export function Figures({
  label,
  items,
}: {
  label: string;
  items: readonly { label: string; value: ReactNode; note?: ReactNode }[];
}) {
  return (
    <div role="group" aria-label={label} className={CARD}>
      <dl className="grid grid-cols-3 gap-3">
        {items.map((item) => (
          <div key={item.label} className="flex min-w-0 flex-col gap-0.5">
            <dt className={CAPTION}>{item.label}</dt>
            <dd className="text-sm break-words">{item.value}</dd>
            {item.note !== undefined && item.note !== null && (
              <dd className="text-xs break-words text-muted">{item.note}</dd>
            )}
          </div>
        ))}
      </dl>
    </div>
  );
}

/** The label/value rows of the technical tab: the label muted, the value in monospace. */
export function FactRows({ rows }: { rows: readonly { label: string; value: ReactNode }[] }) {
  return (
    <div className={CARD}>
      <dl className="grid grid-cols-[180px_1fr] gap-y-2 text-[13px]">
        {rows.map((row) => (
          <div key={row.label} className="col-span-2 grid grid-cols-subgrid">
            <dt className="text-muted">{row.label}</dt>
            <dd className="font-mono break-words">{row.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

/** A line of text with a mark beside it. The mark is decoration: the text says it. */
export function IconLine({ kind, children }: { kind: StatusKind; children: ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <StatusIcon kind={kind} />
      <span className="min-w-0 text-[13px] leading-[19px] break-words">{children}</span>
    </div>
  );
}
