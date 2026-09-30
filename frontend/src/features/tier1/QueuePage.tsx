// The Tier-1 queue (spec §3.1, /queue): the clusters of alerts waiting for a decision, most serious first,
// with the ① suggestion beside each. The view (band, category, agent, "mine", page) is in the URL, so a
// reload or a shared link keeps it; the server does the filtering, and the counts of the band chips are its
// own (`counts_by_band`). It is live: the socket of LiveProvider refetches the query on a change, and with
// no socket the query polls every 30 s.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useMemo } from "react";
import { Link, useSearchParams } from "react-router";
import { fetchQueue, type QueueFilters, type QueueRow } from "../../api/tier1";
import { BandBadge } from "../../components/Badge";
import { DataTable, type Column } from "../../components/DataTable";
import { formatTime } from "../../format";
import { useLiveStatus } from "../../live/LiveProvider";
import { S } from "../../strings";
import { AiCell } from "./AiCell";
import { aiStateOfRow } from "./aiState";
import { BandChips, QueueFilterBar } from "./QueueFilterBar";
import { QueuePagination } from "./QueuePagination";
import { readView, viewToParams, type QueueView } from "./queueParams";

/** With no live socket the page asks again this often (spec §3). */
export const OFFLINE_POLL_MS = 30_000;

const COLUMNS: readonly Column<QueueRow>[] = [
  { id: "band", header: S.queue.col.band, cell: (row) => <BandBadge label={row.risk_band} /> },
  {
    id: "description",
    header: S.queue.col.description,
    className: "max-w-xl",
    cell: (row) => (
      <>
        <Link
          to={`/alerts/${encodeURIComponent(row.alert_id)}`}
          className="underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-text"
        >
          {row.description}
        </Link>
        <span className="ml-2 font-mono text-xs text-muted">{S.queue.rule(row.rule_id)}</span>
        {row.needs_retriage && (
          <span
            role="img"
            aria-label={S.queue.retriage}
            title={S.queue.retriage}
            className="ml-2 text-medium"
          >
            {S.queue.retriageMark}
          </span>
        )}
      </>
    ),
  },
  { id: "category", header: S.queue.col.category, cell: (row) => row.category },
  { id: "agent", header: S.queue.col.agent, cell: (row) => row.agent_name },
  {
    id: "occurrences",
    header: S.queue.col.occurrences,
    className: "text-right tabular-nums",
    cell: (row) => row.occurrence_count,
  },
  {
    id: "lastSeen",
    header: S.queue.col.lastSeen,
    className: "whitespace-nowrap",
    cell: (row) => formatTime(row.last_seen_at),
  },
  {
    id: "ai",
    header: S.queue.col.ai,
    // The ① cell is worded from `aiStateOfRow` alone: this page decides nothing about it.
    cell: (row) => <AiCell state={aiStateOfRow(row)} />,
  },
];

export function QueuePage() {
  const [params, setParams] = useSearchParams();
  const view = useMemo(() => readView(params), [params]);
  const { filters, page } = view;
  const live = useLiveStatus();

  const query = useQuery({
    queryKey: ["queue", filters, page],
    queryFn: ({ signal }) => fetchQueue(filters, page, signal),
    // The rows stay on screen (dimmed, aria-busy) while the next filter or page loads.
    placeholderData: keepPreviousData,
    refetchInterval: live === "offline" ? OFFLINE_POLL_MS : false,
  });

  const show = (next: QueueView) => setParams(viewToParams(next));
  // A new filter starts again from the first page.
  const filter = (next: QueueFilters) => show({ filters: next, page: 1 });
  const filtered =
    Boolean(filters.band || filters.category || filters.agent) || filters.status === "mine";
  const narrowed = Boolean(filters.band || filters.category || filters.agent);
  const data = query.data;

  function emptyText(total: number): string {
    if (total > 0) return S.queue.pageEmpty;
    if (narrowed) return S.queue.noMatch;
    return filters.status === "mine" ? S.queue.emptyMine : S.queue.empty;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-lg font-semibold">{S.queue.title}</h1>
        {data !== undefined && (
          <p className="text-sm text-muted">
            {filters.status === "mine" ? S.queue.countMine(data.total) : S.queue.count(data.total)}
          </p>
        )}
      </div>

      {data !== undefined && (
        <BandChips
          counts={data.counts_by_band}
          band={filters.band}
          onPick={(band) => {
            const next: QueueFilters = { ...filters };
            delete next.band;
            if (band !== undefined) next.band = band;
            filter(next);
          }}
        />
      )}

      <QueueFilterBar
        key={`${filters.category ?? ""}\u0000${filters.agent ?? ""}`}
        filters={filters}
        filtered={filtered}
        onChange={filter}
        onClear={() => filter({ status: "queued" })}
      />

      {query.isError && (
        <div
          role="alert"
          className="flex items-center gap-3 rounded border border-critical px-3 py-2 text-sm text-critical"
        >
          <span>{S.queue.loadError}</span>
          <button
            type="button"
            onClick={() => void query.refetch()}
            className="rounded border border-critical px-2 py-0.5 hover:bg-surface focus-visible:outline-2 focus-visible:outline-text"
          >
            {S.common.retry}
          </button>
        </div>
      )}

      {data === undefined ? (
        !query.isError && (
          <p role="status" className="text-sm text-muted">
            {S.common.loading}
          </p>
        )
      ) : (
        <>
          <DataTable
            label={S.queue.tableLabel}
            columns={COLUMNS}
            rows={data.rows}
            rowKey={(row) => row.alert_id}
            empty={emptyText(data.total)}
            busy={query.isPlaceholderData}
          />
          <QueuePagination
            view={view}
            page={data.page}
            pageSize={data.page_size}
            total={data.total}
          />
        </>
      )}
    </div>
  );
}
