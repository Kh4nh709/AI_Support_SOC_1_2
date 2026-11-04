// `/admin/lab` (P14-T10, DEC-213, spec §6): the lab runs, and the form that records one. A run is a name, a purpose
// (`kb`, building the knowledge base, or `test`, being scored) and the window of time its alerts were received in;
// each row says how many of its alerts carry a hand label ("Đã gán x/y") and opens the run's own page, where the
// alerts are labelled. TanStack Query owns the one read (`adminKeys.labRuns`); the one write is the create panel's.
//
// The times are shown with the console's formatter (format.ts, Asia/Ho_Chi_Minh), and the panel takes them in the
// same zone. Nothing here reads ① or ②.
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { adminErrorOf, listLabRuns, type LabRun } from "../../api/admin";
import { DataTable, type Column } from "../../components/DataTable";
import { PageError } from "../../components/PageError";
import { Toast } from "../../components/Toast";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";
import { adminKeys } from "./adminKeys";
import { LabRunCreatePanel } from "./LabRunCreatePanel";

const T = S.admin.lab.runsPage;

function TableSkeleton() {
  return (
    <div
      role="status"
      aria-busy="true"
      className="space-y-2.5 rounded-[10px] border border-border bg-surface p-4"
    >
      <span className="sr-only">{S.common.loading}</span>
      {["a", "b", "c", "d"].map((key) => (
        <div key={key} className="h-10 animate-pulse rounded-md bg-[#1c2530]" />
      ))}
    </div>
  );
}

const COLUMNS: readonly Column<LabRun>[] = [
  {
    id: "name",
    header: T.col.name,
    cell: (run) => (
      <Link
        to={`/admin/lab/${encodeURIComponent(run.run_id)}`}
        className="font-semibold break-words underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text"
      >
        {run.name}
      </Link>
    ),
  },
  {
    id: "purpose",
    header: T.col.purpose,
    cell: (run) => labelOf(S.admin.lab.purpose, run.purpose),
  },
  {
    id: "window",
    header: T.col.window,
    cell: (run) => (
      <span className="text-[#aeb9c6]">
        {S.admin.lab.window(formatDateTime(run.starts_at), formatDateTime(run.ends_at))}
      </span>
    ),
  },
  {
    id: "labelled",
    header: T.col.labelled,
    className: "tabular-nums",
    cell: (run) => S.admin.lab.progress(run.labelled, run.total),
  },
];

export function LabRunsPage() {
  const query = useQuery({ queryKey: adminKeys.labRuns, queryFn: listLabRuns });
  const [notice, setNotice] = useState<string | null>(null);

  if (query.data === undefined && query.isError) {
    const error = adminErrorOf(query.error);
    // A role that is gone cannot read the list again: no retry for it.
    if (error.kind === "reason" && error.reason === "forbidden") {
      return <PageError title={S.admin.reason.forbidden} />;
    }
    return <PageError title={S.admin.common.loadError} onRetry={() => void query.refetch()} />;
  }

  const runs = query.data?.runs ?? null;

  return (
    // The list on the left, the create panel beside it; under 1440 wide the panel goes under the table.
    <div className="grid grid-cols-1 items-start gap-x-6 gap-y-4 min-[1440px]:grid-cols-[minmax(0,1fr)_380px]">
      <div className="min-w-0 space-y-4">
        <div className="space-y-1">
          <h1 className="text-[26px] font-semibold">{S.admin.lab.title.runs}</h1>
          <p className="max-w-3xl text-sm text-[#aeb9c6]">{T.subtitle}</p>
          <p className="min-h-5 text-sm text-[#aeb9c6]">{runs !== null && T.count(runs.length)}</p>
        </div>

        {runs === null ? (
          <TableSkeleton />
        ) : (
          <DataTable
            label={T.tableLabel}
            columns={COLUMNS}
            rows={runs}
            rowKey={(run) => run.run_id}
            empty={T.empty}
            busy={query.isFetching}
          />
        )}
      </div>

      <LabRunCreatePanel onCreated={setNotice} />

      {notice !== null && (
        <div className="fixed right-4 bottom-4 z-40 w-96">
          <Toast onClose={() => setNotice(null)}>
            <p>{notice}</p>
          </Toast>
        </div>
      )}
    </div>
  );
}
