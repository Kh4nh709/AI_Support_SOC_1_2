// `/admin/lab/:runId` (P14-T10, DEC-213, spec §6): the alerts of one lab run, oldest first, and the buttons that label
// each of them TP (a real attack) or FP (not an attack). Those labels are the ground truth of the measurement.
//
// BLIND (DEC-101): the page shows the alert's own fields and its label, nothing of ① or ②. It calls three routes, all
// under /api/admin/lab (the alerts of the run, and the label PUT and DELETE of LabAlertRow), links to nothing, and
// renders no object whole (LabRunPage.test.tsx reads this file and LabAlertRow.tsx for that).
//
// One infinite query holds the pages loaded ("Tải thêm" asks for the next after the last alert id). A label is written
// by the row; once the server has said yes, the row's alert and the counter "Đã gán x/y" are set in that cache
// (`withLabel`), and nothing is read again: a refetch of an infinite query reads every page loaded, which is a reload
// of the page. The counter is the run's `labelled` and `total` of the first page, moved by the one label.
//
// Two things keep that cache true to the server (P14-T10 fix round 1). A read of the run that is already out when a
// write lands would bring back the labels it took before the write (a refetch reads every page loaded, one after the
// other): `labelled` cancels it before it sets the cache. And a focus of the window does not start such a read
// (`refetchOnWindowFocus: false`): it would re-read up to a hundred alerts, raw logs included, for every page loaded.
// The one read that does follow a write is the one that replaces a cancelled REFETCH (not a cancelled "Tải thêm"): the
// refetch's own news was cancelled with it, so the run is read again after the write (final fix wave, item 42).
import { useInfiniteQuery, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { Link, useParams } from "react-router";
import {
  getLabRunAlerts,
  labErrorOf,
  type LabAlertsResponse,
  type LabLabel,
} from "../../api/admin";
import { PageError } from "../../components/PageError";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";
import { adminKeys, invalidateAfter } from "./adminKeys";
import { LabAlertRow } from "./LabAlertRow";
import { withLabel } from "./labModel";

const R = S.admin.lab.runPage;

const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";

function Skeleton() {
  return (
    <div
      role="status"
      aria-busy="true"
      className="space-y-2.5 rounded-[10px] border border-border bg-surface p-4"
    >
      <span className="sr-only">{S.common.loading}</span>
      {["a", "b", "c"].map((key) => (
        <div key={key} className="h-16 animate-pulse rounded-md bg-[#1c2530]" />
      ))}
    </div>
  );
}

function BackLink({ children }: { children: string }) {
  return (
    <Link
      to="/admin/lab"
      className={`text-sm text-[#aeb9c6] underline underline-offset-2 hover:text-text ${FOCUS}`}
    >
      {children}
    </Link>
  );
}

type Pages = InfiniteData<LabAlertsResponse, string | null>;

export function LabRunPage() {
  const { runId = "" } = useParams();
  const client = useQueryClient();
  const key = adminKeys.labRun(runId);
  const query = useInfiniteQuery({
    queryKey: key,
    queryFn: ({ pageParam }) => getLabRunAlerts(runId, { after: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_after,
    refetchOnWindowFocus: false,
  });

  // The button "Tải thêm" is disabled while anything of the run is being read; the focus it had is given back when the
  // read is over (a disabled button drops it), so a keyboard user can press it again. Only if the focus is nowhere
  // (or still on the button): an admin who went on labelling keeps the focus where they put it, and the page does not
  // scroll to the button (P14 final fix wave, item 41).
  const loadMore = useRef<HTMLButtonElement>(null);
  const refocus = useRef(false);
  const fetching = query.isFetching;
  useEffect(() => {
    if (fetching || !refocus.current) return;
    refocus.current = false;
    const active = document.activeElement;
    if (active === null || active === document.body || active === loadMore.current) {
      loadMore.current?.focus({ preventScroll: true });
    }
  }, [fetching]);

  /**
   * The server set (or cleared) a label: the row and the counter change in the cache, and nothing is read again. A
   * read of the run that is out is cancelled first, and what it had read is discarded: it took its snapshot before this
   * write, and would bring the old label and the old counter back (a cancelled "Tải thêm" is pressed again). The one
   * exception: when the read it cancelled was a refetch of the loaded pages (not a "Tải thêm"), its news went with
   * it, so the run is read once more now, a read that starts after the write (P14 final fix wave, item 42).
   */
  const labelled = async (alertId: string, label: LabLabel | null) => {
    const state = client.getQueryState(key);
    const refetching =
      state?.fetchStatus === "fetching" &&
      state.data !== undefined &&
      state.fetchMeta?.fetchMore === undefined;
    await client.cancelQueries({ queryKey: key });
    client.setQueryData<Pages>(key, (data) =>
      data === undefined ? data : withLabel(data, alertId, label),
    );
    if (refetching) void client.invalidateQueries({ queryKey: key });
    // The list of runs shows a counter of its own, and the audit page the event: both are stale, neither is on screen.
    void invalidateAfter(client, label === null ? "deleteLabLabel" : "putLabLabel");
  };

  if (query.data === undefined && query.isError) {
    const { kind, status } = labErrorOf(query.error);
    // A run that is not there (404), or an address that is no run id (422): nothing to retry.
    if (kind === "not_found" || status === 404 || status === 422) {
      return (
        <div className="space-y-3">
          <h1 className="text-[26px] font-semibold">{R.notFound}</h1>
          <BackLink>{R.backToRuns}</BackLink>
        </div>
      );
    }
    // A role that is gone cannot read the run again: no retry for it.
    if (status === 403) return <PageError title={S.admin.reason.forbidden} />;
    return <PageError title={S.admin.common.loadError} onRetry={() => void query.refetch()} />;
  }

  const first = query.data?.pages[0];
  const run = first?.run ?? null;
  const alerts = query.data?.pages.flatMap((page) => page.alerts) ?? [];

  return (
    <div className="space-y-4">
      <BackLink>{R.back}</BackLink>

      <div className="space-y-1.5">
        <h1 className="text-[26px] font-semibold break-words">
          {run?.name ?? S.admin.lab.title.run}
        </h1>
        {run !== null && (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-[#aeb9c6]">
            <span className="rounded bg-[#1c2530] px-2 py-0.5 text-xs font-semibold text-text">
              {labelOf(S.admin.lab.purpose, run.purpose)}
            </span>
            <span>
              <span className="text-muted">{R.windowLabel}</span>{" "}
              {S.admin.lab.window(formatDateTime(run.starts_at), formatDateTime(run.ends_at))}
            </span>
            <p aria-live="polite" className="font-semibold tabular-nums text-text">
              {S.admin.lab.progress(run.labelled, run.total)}
            </p>
          </div>
        )}
        <p className="max-w-3xl text-sm text-[#aeb9c6]">{R.subtitle}</p>
      </div>

      {run === null ? (
        <Skeleton />
      ) : alerts.length === 0 ? (
        <p className="rounded-[10px] border border-border bg-surface px-5 py-6 text-center text-sm text-muted">
          {R.empty}
        </p>
      ) : (
        <>
          <ol aria-label={R.listLabel} className="space-y-3">
            {alerts.map((alert) => (
              <LabAlertRow key={alert.alert_id} alert={alert} onLabelled={labelled} />
            ))}
          </ol>
          <div className="flex flex-wrap items-center gap-3">
            <p aria-live="polite" className="text-[13px] text-muted">
              {R.shown(alerts.length)}
            </p>
            {query.hasNextPage && (
              <button
                ref={loadMore}
                type="button"
                // Disabled while ANY read of the run is out, a refetch included: pressed then, it would join that
                // read and fetch nothing, and say nothing. `cancelRefetch: false`: a second press in the same tick,
                // before React has rendered the first, joins the request that is out instead of sending another.
                disabled={fetching}
                onClick={() => {
                  refocus.current = true;
                  void query.fetchNextPage({ cancelRefetch: false });
                }}
                className={`h-[34px] rounded-md border border-[#2e3a48] px-3 text-[13px] text-[#c9d3df] hover:bg-ground disabled:cursor-wait disabled:opacity-60 ${FOCUS}`}
              >
                {fetching ? R.loadingMore : R.loadMore}
              </button>
            )}
            {query.isFetchNextPageError && (
              <p role="alert" className="text-[13px] text-[#fda4af]">
                {R.loadMoreFailed}
              </p>
            )}
          </div>
        </>
      )}
    </div>
  );
}
