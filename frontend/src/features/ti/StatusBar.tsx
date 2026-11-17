// The status bar (spec section 8, 1): when the last successful import finished (GMT+7) and how many IOCs it made new, and a red banner
// when the data is stale (no successful import within the server's `stale_after_hours`, or none ever). A run that failed after the last
// good one is said beside it: the list still holds the earlier data.
import { useQuery } from "@tanstack/react-query";
import { fetchTiStatus, type TiStatus } from "../../api/ti";
import { formatDateTime } from "../../format";
import { S } from "../../strings";
import { SectionError } from "./Notices";
import { TI_POLL_MS, tiKeys } from "./tiQueries";

function Body({ status }: { status: TiStatus }) {
  const good = status.latest_success;
  const failed = status.latest !== null && status.latest.status === "failed" ? status.latest : null;
  return (
    <>
      {status.stale && (
        <div
          role="alert"
          className="rounded border border-critical bg-critical-bg px-3 py-2 text-sm font-medium text-critical"
        >
          {good === null ? S.ti.status.staleNever : S.ti.status.stale(status.stale_after_hours)}
        </div>
      )}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded border border-border bg-surface px-3 py-2 text-sm">
        {good === null ? (
          <span className="text-muted">{S.ti.status.never}</span>
        ) : (
          <>
            <span className="text-muted">{S.ti.status.last}</span>
            <span className="font-medium">{S.ti.status.at(formatDateTime(good.finished_at))}</span>
            <span>{S.ti.status.newCount(good.rows_new)}</span>
            <span className="text-muted">{S.ti.status.updatedCount(good.rows_updated)}</span>
            <span className="text-muted">{S.ti.status.errorCount(good.rows_error)}</span>
          </>
        )}
      </div>
      {failed !== null && (
        <p className="text-sm text-high">
          {S.ti.status.failedLast(formatDateTime(failed.finished_at))}
        </p>
      )}
    </>
  );
}

export function StatusBar() {
  const query = useQuery<TiStatus>({
    queryKey: tiKeys.status,
    queryFn: ({ signal }) => fetchTiStatus(signal),
    refetchInterval: TI_POLL_MS,
  });
  return (
    <section aria-label={S.ti.status.label} className="flex flex-col gap-2">
      {query.data !== undefined ? (
        <Body status={query.data} />
      ) : query.isError ? (
        <SectionError
          error={query.error}
          message={S.ti.loadError.status}
          onRetry={() => void query.refetch()}
        />
      ) : (
        <p role="status" className="text-sm text-muted">
          {S.common.loading}
        </p>
      )}
    </section>
  );
}
