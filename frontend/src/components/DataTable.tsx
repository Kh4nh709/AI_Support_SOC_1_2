// A plain data table: a caption for the screen reader, column headers, and a cell renderer per column.
// It holds no state and fetches nothing; the page passes the rows. A row's cells are React text or elements
// the page built, so a value from the server is never taken for markup.
import type { ReactNode } from "react";

export type Column<T> = {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Extra classes of the column's cells, e.g. `text-right` for a number. */
  className?: string;
};

export function DataTable<T>({
  label,
  columns,
  rows,
  rowKey,
  empty,
  busy = false,
}: {
  /** What the table is, for the screen reader (its caption). */
  label: string;
  columns: readonly Column<T>[];
  rows: readonly T[];
  rowKey: (row: T) => string;
  /** Shown in place of the rows when there are none. */
  empty?: ReactNode;
  /** The rows on screen are being replaced. */
  busy?: boolean;
}) {
  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full border-collapse text-left text-sm" aria-busy={busy}>
        <caption className="sr-only">{label}</caption>
        <thead className="bg-surface text-xs text-muted">
          <tr>
            {columns.map((column) => (
              <th
                key={column.id}
                scope="col"
                className={`px-3 py-2 font-medium ${column.className ?? ""}`}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-center text-muted">
                {empty}
              </td>
            </tr>
          ) : (
            rows.map((row) => (
              <tr key={rowKey(row)} className="border-t border-border hover:bg-surface">
                {columns.map((column) => (
                  <td key={column.id} className={`px-3 py-2 align-top ${column.className ?? ""}`}>
                    {column.cell(row)}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
