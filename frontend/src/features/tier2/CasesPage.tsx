// `/cases` (spec §4): the case list, `investigating` first and then newest first, in the order the
// server sends it, paged by offset. TanStack Query owns the read: one query per page, `["cases", page]`.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";
import { CASE_PAGE_SIZE, listCases, type CaseRow } from "../../api/tier2";
import { DataTable, type Column } from "../../components/DataTable";
import { RecordWorkspace, type PickRecord } from "../../components/RecordWorkspace";
import { formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { lastAnalysedText } from "./lastAnalysed";
import { BUTTON, ErrorNotice } from "./parts";
import { tier2Keys } from "./queryKeys";

const caseKey = (row: CaseRow) => row.case_id;
const caseTitle = (row: CaseRow) => row.title || row.case_id;
const caseHref = (row: CaseRow) => `/cases/${encodeURIComponent(row.case_id)}`;

function columnsFor(pick: PickRecord<CaseRow>): Column<CaseRow>[] {
  const col = S.case.col;
  return [
    {
      id: "title",
      header: col.title,
      cell: (row) => (
        <div className="flex items-start justify-between gap-3">
          <Link
            to={caseHref(row)}
            className="min-w-0 font-semibold underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-text"
          >
            {caseTitle(row)}
          </Link>
          {pick(row)}
        </div>
      ),
    },
    { id: "caseStatus", header: col.status, cell: (row) => labelOf(S.caseStatus, row.status) },
    {
      id: "severity",
      header: col.severity,
      cell: (row) => (
        <span data-severity={row.severity} className="soc-severity">
          {labelOf(S.severity, row.severity)}
        </span>
      ),
    },
    { id: "clusters", header: col.clusters, cell: (row) => row.cluster_count },
    { id: "alerts", header: col.alerts, cell: (row) => row.occurrence_count },
    { id: "created", header: col.created, cell: (row) => formatTime(row.created_at) },
    {
      id: "lastAnalysed",
      header: col.lastAnalysed,
      cell: (row) => lastAnalysedText(row, formatTime),
    },
  ];
}

export function CasesPage() {
  const [page, setPage] = useState(0);
  const query = useQuery({
    queryKey: tier2Keys.casesPage(page),
    queryFn: () => listCases(page * CASE_PAGE_SIZE, CASE_PAGE_SIZE),
    // The rows of the page just left stay on screen (marked busy) until the next page answers. It is the
    // same list, so no other case's data is ever shown as this one's.
    placeholderData: keepPreviousData,
  });
  const data = query.data ?? null;
  const error: unknown = query.isError ? query.error : null;
  // True while a read of the page asked for is out: the rows in hand are then a page kept from before (the
  // placeholder) or this page's own from the cache, being read again.
  const loading = query.isPending || query.isPlaceholderData || query.isFetching;

  const rows = data ?? [];
  // A short page is the last one; the route answers a bare list with no total.
  const hasNext = !loading && error === null && rows.length === CASE_PAGE_SIZE;
  const hasPrev = !loading && page > 0;

  return (
    <div className="soc-workspace min-w-0 space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{S.case.listTitle}</h1>

      {error !== null ? (
        <ErrorNotice message={S.common.unknownError} onRetry={() => void query.refetch()} />
      ) : data === null || (loading && rows.length === 0) ? (
        // An empty page still in hand belongs to the offset the reader just left, so it says nothing yet.
        <p role="status">{S.common.loading}</p>
      ) : rows.length === 0 ? (
        // Past the last page the list is not empty: only this page is, and "Trước" goes back.
        <p>{page > 0 ? S.case.pastEnd : S.case.empty}</p>
      ) : (
        <RecordWorkspace
          key={page}
          rows={rows}
          rowKey={caseKey}
          title={caseTitle}
          href={caseHref}
          action={S.workspace.openCase}
          fields={(row) => [
            [S.case.col.status, labelOf(S.caseStatus, row.status)],
            [S.case.col.lastAnalysed, lastAnalysedText(row, formatTime)],
            [S.case.col.clusters, row.cluster_count],
            [S.case.col.alerts, row.occurrence_count],
            [S.case.col.severity, labelOf(S.severity, row.severity)],
            [S.case.col.created, formatTime(row.created_at)],
          ]}
          list={(selected, pick, afterRow) => (
            <DataTable
              label={S.case.listTitle}
              columns={columnsFor(pick)}
              rows={rows}
              rowKey={caseKey}
              busy={loading}
              cards={{ selected, afterRow }}
            />
          )}
        />
      )}

      <div className="flex gap-3">
        <button
          type="button"
          className={BUTTON}
          disabled={!hasPrev}
          onClick={() => setPage(Math.max(0, page - 1))}
        >
          {S.common.prev}
        </button>
        <button
          type="button"
          className={BUTTON}
          disabled={!hasNext}
          onClick={() => setPage(page + 1)}
        >
          {S.common.next}
        </button>
      </div>
    </div>
  );
}
