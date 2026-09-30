// src/components/DataTable.test.tsx — a caption and column headers for the screen reader, a cell renderer
// per column, an empty row, and a busy mark while the rows are being replaced.
import { render, screen, within } from "@testing-library/react";
import { DataTable, type Column } from "./DataTable";

type Item = { id: string; name: string; n: number };
const columns: Column<Item>[] = [
  { id: "name", header: "Tên", cell: (r) => r.name },
  { id: "n", header: "Số", cell: (r) => r.n, className: "text-right" },
];
const rows: Item[] = [
  { id: "a", name: "một", n: 1 },
  { id: "b", name: "hai", n: 2 },
];

describe("DataTable", () => {
  it("has a caption, column headers with scope, and a row per item", () => {
    render(<DataTable label="Bảng thử" columns={columns} rows={rows} rowKey={(r) => r.id} />);
    const table = screen.getByRole("table", { name: "Bảng thử" });
    const headers = within(table).getAllByRole("columnheader");
    expect(headers.map((h) => h.textContent)).toEqual(["Tên", "Số"]);
    for (const h of headers) expect(h).toHaveAttribute("scope", "col");
    expect(within(table).getAllByRole("row")).toHaveLength(3); // the header row and two rows
    expect(within(screen.getByRole("row", { name: /hai/ })).getAllByRole("cell")[1]).toHaveClass(
      "text-right",
    );
  });

  it("shows the empty text in one cell that spans every column", () => {
    render(
      <DataTable label="x" columns={columns} rows={[]} rowKey={(r) => r.id} empty="Chưa có gì" />,
    );
    const cell = screen.getByRole("cell", { name: "Chưa có gì" });
    expect(cell).toHaveAttribute("colspan", "2");
  });

  it("marks the table busy while its rows are being replaced", () => {
    const { rerender } = render(
      <DataTable label="x" columns={columns} rows={rows} rowKey={(r) => r.id} busy />,
    );
    expect(screen.getByRole("table")).toHaveAttribute("aria-busy", "true");
    rerender(<DataTable label="x" columns={columns} rows={rows} rowKey={(r) => r.id} />);
    expect(screen.getByRole("table")).toHaveAttribute("aria-busy", "false");
  });

  it("shows a value that looks like markup as text", () => {
    const hostile = [{ id: "h", name: "<img src=x onerror=alert(1)>", n: 0 }];
    const { container } = render(
      <DataTable label="x" columns={columns} rows={hostile} rowKey={(r) => r.id} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });

  // P10-T14: a page that sorts marks its sorted column; a column that says nothing has no aria-sort at all.
  it("puts aria-sort on the header of a column that names one, and on no other", () => {
    const sorted: Column<Item>[] = [
      { id: "name", header: "Tên", cell: (r) => r.name },
      { id: "n", header: "Số", cell: (r) => r.n, ariaSort: "descending" },
    ];
    render(<DataTable label="x" columns={sorted} rows={rows} rowKey={(r) => r.id} />);
    const [name, n] = screen.getAllByRole("columnheader");
    expect(name).not.toHaveAttribute("aria-sort");
    expect(n).toHaveAttribute("aria-sort", "descending");
  });
});
