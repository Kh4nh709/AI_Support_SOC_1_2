// The read-only matrix of role to function under the users table (the canvas's "Quyền theo vai trò", spec §4.2):
// static text from `strings.ts`, nine rows by three roles. It is a statement of what each role may do, not a
// switch: the server's `require_role` is what enforces it.
import { useId } from "react";
import { DataTable, type Column } from "../../components/DataTable";
import { S } from "../../strings";

const M = S.admin.usersPage.matrix;

type Row = (typeof M.rows)[number];

/** "có" in green, or a dash that a screen reader says as "không": a bare "—" would be read as nothing. */
function Cell({ allowed }: { allowed: boolean }) {
  return allowed ? (
    <span className="text-[#9ff0c5]">{M.yes}</span>
  ) : (
    <span className="text-[#5e6b7a]">
      <span aria-hidden="true">{M.no}</span>
      <span className="sr-only">{M.noSpoken}</span>
    </span>
  );
}

const COLUMNS: readonly Column<Row>[] = [
  { id: "feature", header: M.feature, cell: (row) => row[0] },
  {
    id: "tier1",
    header: "tier1",
    cell: (row) => <Cell allowed={row[1]} />,
    className: "w-28 text-center",
  },
  {
    id: "tier2",
    header: "tier2",
    cell: (row) => <Cell allowed={row[2]} />,
    className: "w-28 text-center",
  },
  {
    id: "admin",
    header: "admin",
    cell: (row) => <Cell allowed={row[3]} />,
    className: "w-28 text-center",
  },
];

export function RoleMatrix() {
  const titleId = useId();
  return (
    <section
      aria-labelledby={titleId}
      className="space-y-3 rounded-[10px] border border-border bg-surface p-5"
    >
      <div className="flex items-baseline gap-2.5">
        <h2 id={titleId} className="flex-1 text-[15px] font-semibold">
          {M.title}
        </h2>
        <span className="text-xs text-muted">{M.note}</span>
      </div>
      <DataTable label={M.title} columns={COLUMNS} rows={M.rows} rowKey={(row) => row[0]} />
    </section>
  );
}
