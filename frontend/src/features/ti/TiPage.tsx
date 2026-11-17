// The page "Threat Intel" (`/threat-intel`, all three roles; DEC-224): the abuse.ch IOCs the host's daily script collects, through the
// importer and the API. Top to bottom: the status bar (and its stale banner), the four KPI cards, the two charts, then the filters, the
// export (the admin's) and the table of IOCs with its pagination and a detail panel. The view (the filters, the search, the page) is in
// the URL; the status and the stats ask again every five minutes. Every IOC field is text from a public feed: printed as text, a value
// that is a URL, a domain or an address defanged, never a link and never fetched; the copy button copies the original; the one link is
// the reference of an IOC when it is one of abuse.ch's own pages. Nothing for matching IOCs against logs or for AI summaries is built.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { fetchTiIocs, type TiIoc, type TiListResponse } from "../../api/ti";
import { DataTable } from "../../components/DataTable";
import { S } from "../../strings";
import { ExportControl } from "./ExportControl";
import { SectionError } from "./Notices";
import { StatsSection } from "./StatsSection";
import { StatusBar } from "./StatusBar";
import { TiDetail } from "./TiDetail";
import { TiFilters } from "./TiFilters";
import { TiPagination } from "./TiPagination";
import { filtersOf, listQueryOf, readView, viewToParams, type TiView } from "./tiParams";
import { tiKeys } from "./tiQueries";
import { tiColumns } from "./TiTable";

export function TiPage() {
  const [params, setParams] = useSearchParams();
  const view = useMemo(() => readView(params), [params]);

  const query = useQuery<TiListResponse>({
    queryKey: tiKeys.list(view),
    queryFn: ({ signal }) => fetchTiIocs(listQueryOf(view), signal),
    // The rows stay on screen (dimmed, aria-busy) while the next filter or page loads.
    placeholderData: keepPreviousData,
  });

  // The page's own state: the IOC of the open panel (the row as it was served, so the panel stays when the list moves to another
  // page), and the button that opened it, so the focus can go back to it when the panel is closed.
  const [detail, setDetail] = useState<TiIoc | null>(null);
  const [opener, setOpener] = useState<HTMLElement | null>(null);

  const show = (next: TiView) => setParams(viewToParams(next));
  const openDetail = (ioc: TiIoc, from: HTMLElement) => {
    setOpener(from);
    setDetail(ioc);
  };
  const closeDetail = () => {
    setDetail(null);
    setOpener(null);
    if (opener?.isConnected) opener.focus();
  };

  const data = query.data;
  const columns = useMemo(() => tiColumns({ onOpen: openDetail }), []);
  const filtered = viewToParams({ ...view, page: 1 }).toString() !== "";
  // The panel follows its IOC when the list still has it (a refetch changed a field), and keeps the one it was opened with when not.
  const shownDetail =
    detail === null ? null : (data?.rows.find((row) => row.id === detail.id) ?? detail);

  function emptyText(total: number): string {
    if (total > 0) return S.ti.pageEmpty;
    return filtered ? S.ti.emptyFiltered : S.ti.empty;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="text-lg font-semibold">{S.ti.title}</h1>
        {data !== undefined && <p className="text-sm text-muted">{S.ti.count(data.total)}</p>}
      </div>

      <StatusBar />
      <StatsSection />

      <div className="flex flex-wrap items-start justify-between gap-4">
        <TiFilters view={view} onApply={show} />
        <ExportControl filters={filtersOf(view)} />
      </div>

      {query.isError && (
        <SectionError
          error={query.error}
          message={S.ti.loadError.list}
          onRetry={() => void query.refetch()}
        />
      )}

      <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
        {shownDetail !== null && <TiDetail ioc={shownDetail} onClose={closeDetail} />}
        <div className="flex min-w-0 flex-1 flex-col gap-4">
          {data === undefined ? (
            !query.isError && (
              <p role="status" className="text-sm text-muted">
                {S.common.loading}
              </p>
            )
          ) : (
            <>
              <DataTable
                label={S.ti.tableLabel}
                columns={columns}
                rows={data.rows}
                rowKey={(row) => String(row.id)}
                empty={emptyText(data.total)}
                busy={query.isPlaceholderData}
              />
              <TiPagination
                view={view}
                page={data.page}
                pageSize={data.page_size}
                total={data.total}
              />
              <p className="text-xs text-muted">{S.ti.valueNote}</p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
