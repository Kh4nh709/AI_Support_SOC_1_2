// The page "Phản hồi SOAR" (`/soar`, all three roles): the review tickets the SOAR (n8n) pushes, and what an analyst does
// with them: keep, undo, or call a false positive. The view (the tab, the search, the page) is in the URL; the list asks
// again every 20 s (there is no socket for these tickets); a ticket's buttons are the server's own `allowed_decisions`
// for this caller. Undo and false positive go through a dialog with a note; keep is sent at once. What each press says
// stays on its row (see `useDecisions`), and none of the page's state (the dialog, its note, the open detail panel, an error
// line) is in the query cache, so a refetch never wipes it. Everything n8n wrote is text.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import {
  fetchSoarReviews,
  SOAR_PAGE_SIZE,
  type SoarDecision,
  type SoarListResponse,
  type SoarReview,
} from "../../api/soar";
import { useAuth } from "../../auth/AuthProvider";
import { DataTable } from "../../components/DataTable";
import { Toast } from "../../components/Toast";
import { S } from "../../strings";
import { SoarClock } from "./Clock";
import { cleanDeep } from "./model";
import { DecisionDialog, type DialogDecision } from "./DecisionDialog";
import { DetailPanel } from "./DetailPanel";
import { NoticeStrip } from "./Notices";
import { SignalSwitch } from "./SignalSwitch";
import { SearchForm, TabNav } from "./SoarFilters";
import { SoarPagination } from "./SoarPagination";
import { SOAR_LIST_POLL_MS, soarKeys } from "./soarQueries";
import { listQueryOf, readView, viewToParams, type SoarView } from "./soarParams";
import { noticeColumns, reviewColumns } from "./SoarTable";
import { readDismissed, writeDismissed } from "./storage";
import { useDecisions } from "./useDecisions";

/** What the notices above the table are read from: the newest of them, the page does the rest. */
const NOTICE_FETCH = { kind: "notice", page: 1, pageSize: SOAR_PAGE_SIZE } as const;

export function SoarPage({ now = Date.now }: { now?: () => number }) {
  const [params, setParams] = useSearchParams();
  const view = useMemo(() => readView(params), [params]);
  const { session } = useAuth();
  const decisions = useDecisions();

  const query = useQuery<SoarListResponse>({
    queryKey: soarKeys.list(view.tab, view.q, view.page),
    queryFn: ({ signal }) =>
      fetchSoarReviews(listQueryOf(view), signal).then((answer) => cleanDeep(answer)),
    // The rows stay on screen (dimmed, aria-busy) while the next tab, search or page loads.
    placeholderData: keepPreviousData,
    refetchInterval: SOAR_LIST_POLL_MS,
  });
  // The notices above a review tab. On the notices tab the table itself lists them, so this is not asked.
  const notices = useQuery<SoarListResponse>({
    queryKey: soarKeys.notices,
    queryFn: ({ signal }) =>
      fetchSoarReviews(NOTICE_FETCH, signal).then((answer) => cleanDeep(answer)),
    enabled: view.tab !== "notice",
    refetchInterval: SOAR_LIST_POLL_MS,
  });

  // The page's own state: nothing of it lives in the cache, so a refetch cannot touch it.
  const [dialog, setDialog] = useState<{ row: SoarReview; decision: DialogDecision } | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  // The button that opened the panel, so the focus can go back to it when the panel is closed.
  const [opener, setOpener] = useState<HTMLElement | null>(null);
  const [dismissed, setDismissed] = useState<readonly string[]>(readDismissed);
  const dismissedSet = useMemo(() => new Set(dismissed), [dismissed]);

  const show = (next: SoarView) => setParams(viewToParams(next));
  const dismiss = (id: string) => {
    const next = [...dismissed.filter((known) => known !== id), id];
    setDismissed(next);
    writeDismissed(next);
  };
  const press = (row: SoarReview, decision: SoarDecision) => {
    if (decision === "keep") void decisions.run(row, "keep", "");
    else if (decision === "undo" || decision === "fp") setDialog({ row, decision });
  };
  const openDetail = (id: string, from: HTMLElement) => {
    setOpener(from);
    setDetailId(id);
  };
  const closeDetail = () => {
    setDetailId(null);
    setOpener(null);
    if (opener?.isConnected) opener.focus();
  };

  const data = query.data;
  // The ticket of the open dialog as the list has it now (the dialog follows it, see DecisionDialog).
  const liveRow =
    dialog === null
      ? null
      : (data?.rows.find((candidate) => candidate.id === dialog.row.id) ?? null);
  const columns =
    view.tab === "notice"
      ? noticeColumns({ dismissed: dismissedSet, onDismiss: dismiss, onOpen: openDetail })
      : reviewColumns({
          states: decisions.states,
          me: session?.username ?? null,
          focus: decisions.focus,
          onPress: press,
          onOpen: openDetail,
        });

  function emptyText(total: number): string {
    if (total > 0) return S.soar.pageEmpty;
    if (view.q !== "") return S.soar.empty.search;
    return S.soar.empty[view.tab];
  }

  return (
    <SoarClock now={now}>
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-baseline gap-3">
          <h1 className="text-lg font-semibold">{S.soar.title}</h1>
          {data !== undefined && <p className="text-sm text-muted">{S.soar.count(data.total)}</p>}
        </div>

        <SignalSwitch />

        {decisions.toast !== null && (
          <Toast onClose={decisions.closeToast}>{decisions.toast}</Toast>
        )}

        <TabNav view={view} />
        <SearchForm
          key={view.q}
          view={view}
          onSearch={(q) => show({ tab: view.tab, q, page: 1 })}
        />

        {view.tab !== "notice" && notices.data !== undefined && (
          <NoticeStrip notices={notices.data.rows} dismissed={dismissedSet} onDismiss={dismiss} />
        )}

        {query.isError && (
          <div
            role="alert"
            className="flex items-center gap-3 rounded border border-critical px-3 py-2 text-sm text-critical"
          >
            <span>{S.soar.loadError}</span>
            <button
              type="button"
              onClick={() => void query.refetch()}
              className="rounded border border-critical px-2 py-0.5 hover:bg-surface focus-visible:outline-2 focus-visible:outline-text"
            >
              {S.common.retry}
            </button>
          </div>
        )}

        <div className="flex items-start gap-4">
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
                  label={view.tab === "notice" ? S.soar.noticeTableLabel : S.soar.tableLabel}
                  columns={columns}
                  rows={data.rows}
                  rowKey={(row) => row.id}
                  empty={emptyText(data.total)}
                  busy={query.isPlaceholderData}
                />
                <SoarPagination
                  view={view}
                  page={data.page}
                  pageSize={data.page_size}
                  total={data.total}
                />
              </>
            )}
          </div>
          {detailId !== null && <DetailPanel id={detailId} onClose={closeDetail} />}
        </div>
      </div>

      {dialog !== null && (
        <DecisionDialog
          row={dialog.row}
          live={liveRow}
          gone={liveRow === null && data !== undefined && !query.isPlaceholderData}
          decision={dialog.decision}
          onCancel={() => setDialog(null)}
          onConfirm={(note, current) => {
            const { decision } = dialog;
            setDialog(null);
            void decisions.run(current, decision, note);
          }}
        />
      )}
    </SoarClock>
  );
}
