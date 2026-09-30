// The sort controls of the queue (P10-T14, DEC-164): the header of a sortable column, which is a button
// inside its <th>, and the button that goes back to the default risk order. Both only report a click: the
// page puts the new sort in the URL, and the server does the sorting.
import type { QueueSortDir } from "../../api/tier1";
import { S } from "../../strings";

/** The `aria-sort` of the <th> of the sorted column. */
export function ariaSortOf(direction: QueueSortDir): "ascending" | "descending" {
  return direction === "asc" ? "ascending" : "descending";
}

/**
 * The content of a sortable column's header. `direction` is set on the column the rows are sorted by, and
 * then the arrow shows it. The arrow is decoration for the screen reader (the <th> says `aria-sort`), so the
 * button's name stays the column's name.
 */
export function SortHeader({
  label,
  direction,
  onSort,
}: {
  label: string;
  direction: QueueSortDir | undefined;
  onSort: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onSort}
      className="inline-flex items-center gap-1 rounded font-medium hover:text-text focus-visible:outline-2 focus-visible:outline-text"
    >
      {label}
      {direction !== undefined && (
        <span aria-hidden="true" className="text-text">
          {direction === "asc" ? S.queue.sort.asc : S.queue.sort.desc}
        </span>
      )}
    </button>
  );
}

/** "Sắp theo mức rủi ro": pressed while the queue is in the default risk order, and then it changes nothing. */
export function RiskOrderButton({ pressed, onPick }: { pressed: boolean; onPick: () => void }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={() => {
        if (!pressed) onPick();
      }}
      className={`rounded border px-3 py-1 text-sm focus-visible:outline-2 focus-visible:outline-text ${
        pressed ? "border-text font-medium" : "border-border hover:bg-surface"
      }`}
    >
      {S.queue.sort.byRisk}
    </button>
  );
}
