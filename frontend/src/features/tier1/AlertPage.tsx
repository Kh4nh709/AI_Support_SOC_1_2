// The alert page (spec §3.2, /alerts/:alertId): two columns, what Wazuh sent and the console added on the
// left, the ① analysis on the right, and the decision panel at the foot of the left column. TanStack Query
// owns the read (key ["alert", id]): the live socket refetches it when the server says the alert changed,
// and with no socket the page asks again every 30 s. The ① state is not decided here: the column asks
// `aiStateOfView`, which reads what the server sent and nothing else.
import { useQuery } from "@tanstack/react-query";
import { useId, useMemo } from "react";
import { Link, useParams } from "react-router";
import { ApiError } from "../../api/client";
import { fetchAlertView, type AlertView } from "../../api/tier1";
import { useAuth } from "../../auth/AuthProvider";
import { PageError } from "../../components/PageError";
import { useLiveStatus } from "../../live/LiveProvider";
import { OFFLINE_POLL_MS, PENDING_POLL_MS } from "../../live/poll";
import type { LiveStatus } from "../../live/socket";
import { S } from "../../strings";
import { aiStateOfView } from "./aiState";
import { AiColumn } from "./AiColumn";
import {
  Accounts,
  Correlation,
  Enrichment,
  EventDetails,
  Playbook,
  RawLog,
  Summary,
} from "./AlertSections";
import { DecisionPanel } from "./DecisionPanel";

/** A head fetched for a duplicate is fresh for this long after the view that named it. */
const HEAD_FRESH_MS = 5_000;

const LINK = "underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text";

function pollEvery(view: AlertView | undefined, live: LiveStatus): number | false {
  if (view !== undefined && aiStateOfView(view).kind === "pending") return PENDING_POLL_MS;
  return live === "offline" ? OFFLINE_POLL_MS : false;
}

export function AlertPage() {
  const { alertId } = useParams();
  if (!alertId) return <PageError title={S.alert.notFound} />;
  // A new id is a new page: what was typed and said on the last one stays with it.
  return <AlertScreen key={alertId} alertId={alertId} />;
}

function AlertScreen({ alertId }: { alertId: string }) {
  const { session } = useAuth();
  const live = useLiveStatus();
  const infoHeading = useId();

  const query = useQuery({
    queryKey: ["alert", alertId],
    queryFn: ({ signal }) => fetchAlertView(alertId, signal),
    refetchInterval: (q) => pollEvery(q.state.data, live),
  });

  // A duplicate answers with its head (`alert_id` is the head's). The changes the socket reports are the
  // head's, so the head is read under its own key as well, and whichever answer is newer is the one shown.
  const headId = query.data && query.data.alert_id !== alertId ? query.data.alert_id : null;
  const head = useQuery({
    queryKey: ["alert", headId ?? alertId],
    queryFn: ({ signal }) => fetchAlertView(headId ?? alertId, signal),
    enabled: headId !== null,
    initialData: headId !== null ? query.data : undefined,
    initialDataUpdatedAt: query.dataUpdatedAt,
    staleTime: HEAD_FRESH_MS,
  });
  const shown = head.data && head.dataUpdatedAt > query.dataUpdatedAt ? head.data : query.data;
  // What the panel refreshes after a decision: the head, and the id this page was asked for.
  const view = useMemo(
    () => (shown ? { ...shown, requested_alert_id: alertId } : undefined),
    [shown, alertId],
  );

  if (view === undefined) {
    if (query.isError) {
      const missing = query.error instanceof ApiError && query.error.status === 404;
      return missing ? (
        <PageError title={S.alert.notFound} />
      ) : (
        <PageError title={S.alert.loadFailed} onRetry={() => void query.refetch()} />
      );
    }
    return (
      <p role="status" className="text-sm text-muted">
        {S.common.loading}
      </p>
    );
  }

  const isDuplicate = view.alert_id !== alertId;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-sm text-muted">
        <Link to="/queue" className={LINK}>
          {S.nav.queue}
        </Link>
        <span aria-hidden="true">/</span>
        {isDuplicate && (
          <>
            <Link to={`/alerts/${encodeURIComponent(view.alert_id)}`} className={LINK}>
              {view.alert_id}
            </Link>
            <span aria-hidden="true">/</span>
          </>
        )}
        <span className="break-all">{alertId}</span>
      </div>
      <h1 className="text-lg font-semibold break-words">{view.description || view.alert_id}</h1>
      {isDuplicate && <p className="text-sm text-muted">{S.alert.duplicateOf(view.alert_id)}</p>}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_520px]">
        <section aria-labelledby={infoHeading} className="min-w-0 space-y-5">
          <div>
            <h2 id={infoHeading} className="text-xs font-semibold tracking-wide text-muted">
              {S.alert.infoHeading}
            </h2>
            <p className="text-xs text-muted">{S.alert.infoHint}</p>
          </div>
          <Summary view={view} />
          <EventDetails view={view} />
          <RawLog view={view} />
          <Accounts view={view} />
          <Enrichment view={view} />
          <Correlation view={view} />
          <Playbook view={view} />
          {session && <DecisionPanel view={view} me={session} />}
        </section>
        <AiColumn view={view} />
      </div>
    </div>
  );
}
