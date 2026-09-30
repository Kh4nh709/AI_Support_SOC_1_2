// A description list of labelled values, in a grid. An item with no value (null, undefined, false, or an
// empty string) is left out, and a grid with no item left renders nothing at all, so a page that shows a
// block "only when the data is there" passes the items and lets this decide. A value is React text or an
// element the page built, so a string from the server is never taken for markup.
import type { ReactNode } from "react";

export type KeyValueItem = { label: string; value: ReactNode };

/** Whether a value is something to show. `0` is; null, undefined, false and "" are not. */
function hasValue(value: ReactNode): boolean {
  return value !== null && value !== undefined && value !== false && value !== "";
}

/** The items that have a value. */
export function visibleItems(items: readonly KeyValueItem[]): KeyValueItem[] {
  return items.filter((item) => hasValue(item.value));
}

// Whole class names, written out: Tailwind finds a class by reading the source.
const COLUMNS = {
  1: "grid-cols-1",
  2: "grid-cols-1 sm:grid-cols-2",
  3: "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3",
} as const;

export function KeyValueGrid({
  items,
  columns = 2,
}: {
  items: readonly KeyValueItem[];
  columns?: keyof typeof COLUMNS;
}) {
  const shown = visibleItems(items);
  if (shown.length === 0) return null;
  return (
    <dl className={`grid gap-x-6 gap-y-3 text-sm ${COLUMNS[columns]}`}>
      {shown.map((item) => (
        <div key={item.label} className="min-w-0">
          <dt className="text-xs text-muted">{item.label}</dt>
          <dd className="break-words">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
