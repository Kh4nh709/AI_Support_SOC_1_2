// `/cases` (spec §4): the case list, `investigating` first and then newest first, in the order the
// server sends it, paged by offset.
import { useCallback, useId, useState } from "react";
import { Link } from "react-router";
import { CASE_PAGE_SIZE, listCases } from "../../api/tier2";
import { formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { BUTTON, ErrorNotice, PANEL } from "./parts";
import { useLoad } from "./useLoad";

const TH = "px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted";
const TD = "px-3 py-2 align-top";

export function CasesPage() {
  const [offset, setOffset] = useState(0);
  const fetcher = useCallback(() => listCases(offset, CASE_PAGE_SIZE), [offset]);
  const { data, error, loading, reload } = useLoad(fetcher);
  const titleId = useId();

  const rows = data ?? [];
  // A short page is the last one; the route answers a bare list with no total.
  const hasNext = !loading && error === null && rows.length === CASE_PAGE_SIZE;
  const hasPrev = !loading && offset > 0;

  return (
    <div className="space-y-4">
      <h1 id={titleId} className="text-lg font-semibold">
        {S.case.listTitle}
      </h1>

      {error !== null ? (
        <ErrorNotice message={S.common.unknownError} onRetry={() => void reload()} />
      ) : data === null ? (
        <p role="status">{S.common.loading}</p>
      ) : rows.length === 0 ? (
        <p>{S.case.empty}</p>
      ) : (
        <div className={`${PANEL} overflow-x-auto p-0`}>
          <table aria-labelledby={titleId} aria-busy={loading} className="w-full text-sm">
            <thead className="border-b border-border">
              <tr>
                <th scope="col" className={TH}>
                  {S.case.col.title}
                </th>
                <th scope="col" className={TH}>
                  {S.case.col.status}
                </th>
                <th scope="col" className={TH}>
                  {S.case.col.severity}
                </th>
                <th scope="col" className={TH}>
                  {S.case.col.clusters}
                </th>
                <th scope="col" className={TH}>
                  {S.case.col.alerts}
                </th>
                <th scope="col" className={TH}>
                  {S.case.col.created}
                </th>
                <th scope="col" className={TH}>
                  {S.case.col.lastAnalysed}
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.case_id} className="border-b border-border last:border-b-0">
                  <td className={TD}>
                    <Link
                      to={`/cases/${encodeURIComponent(row.case_id)}`}
                      className="text-ai-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-text"
                    >
                      {row.title}
                    </Link>
                  </td>
                  <td className={TD}>{labelOf(S.caseStatus, row.status)}</td>
                  <td className={TD}>{labelOf(S.severity, row.severity)}</td>
                  <td className={TD}>{row.cluster_count}</td>
                  <td className={TD}>{row.occurrence_count}</td>
                  <td className={TD}>{formatTime(row.created_at)}</td>
                  <td className={TD}>
                    {row.last_analyzed_at === null
                      ? S.case.neverAnalysed
                      : formatTime(row.last_analyzed_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="flex gap-3">
        <button
          type="button"
          className={BUTTON}
          disabled={!hasPrev}
          onClick={() => setOffset(Math.max(0, offset - CASE_PAGE_SIZE))}
        >
          {S.common.prev}
        </button>
        <button
          type="button"
          className={BUTTON}
          disabled={!hasNext}
          onClick={() => setOffset(offset + CASE_PAGE_SIZE)}
        >
          {S.common.next}
        </button>
      </div>
    </div>
  );
}
