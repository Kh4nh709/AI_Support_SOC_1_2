// A plain data table: a caption for the screen reader, column headers, and a cell renderer per column.
// It holds no state and fetches nothing; the page passes the rows. A row's cells are React text or elements
// the page built, so a value from the server is never taken for markup.
import { Fragment, type ReactNode } from "react";

export type Column<T> = {
  id: string;
  header: ReactNode;
  cell: (row: T) => ReactNode;
  /** Extra classes of the column's cells, e.g. `text-right` for a number. */
  className?: string;
  /** Set on the one column the rows are sorted by (its `<th>` gets `aria-sort`); left out on every other. */
  ariaSort?: "ascending" | "descending";
  sortable?: boolean;
};

export function DataTable<T>({
  label,
  columns,
  rows,
  rowKey,
  empty,
  busy = false,
  cards,
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
  cards?: { selected: string | undefined; afterRow?: (row: T) => ReactNode };
}) {
  return (
    <div className={`overflow-x-auto border border-border ${cards ? "rounded-xl" : "rounded"}`}>
      <table
        className={`w-full border-collapse text-left text-sm ${cards ? "soc-record-list bg-surface" : ""}`}
        aria-busy={busy}
        role={cards ? "table" : undefined}
      >
        <caption className="sr-only">{label}</caption>
        <thead className="bg-surface text-xs text-muted" role={cards ? "rowgroup" : undefined}>
          <tr role={cards ? "row" : undefined}>
            {columns.map((column) => (
              <th
                key={column.id}
                scope="col"
                role={cards ? "columnheader" : undefined}
                data-sortable={cards && column.sortable ? "" : undefined}
                aria-sort={column.ariaSort}
                className={`px-3 py-2 font-medium ${column.className ?? ""}`}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody role={cards ? "rowgroup" : undefined}>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-center text-muted">
                {empty}
              </td>
            </tr>
          ) : (
            rows.map((row) => {
              const key = rowKey(row);
              const after = cards?.afterRow?.(row);
              return (
                <Fragment key={key}>
                  <tr
                    role={cards ? "row" : undefined}
                    className="border-t border-border hover:bg-surface"
                    data-record={cards ? "" : undefined}
                    data-picked={cards?.selected === key ? "" : undefined}
                  >
                    {columns.map((column) => (
                      <td
                        key={column.id}
                        role={cards ? "cell" : undefined}
                        data-column={cards ? column.id : undefined}
                        data-label={
                          cards && typeof column.header === "string" ? column.header : undefined
                        }
                        className={`px-3 py-2 align-top ${column.className ?? ""}`}
                      >
                        {column.cell(row)}
                      </td>
                    ))}
                  </tr>
                  {after && (
                    <tr role="row" className="soc-preview-row">
                      <td role="cell" colSpan={columns.length}>
                        {after}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
