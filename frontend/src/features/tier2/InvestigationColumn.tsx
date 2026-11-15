// The ② column of the case page (spec §4): what the case assistant made of the case. It reads the state
// from the server (TanStack Query owns the read), starts an analysis on Phân tích, and polls every 3 s
// while one is running. It stops on done, failed or stalled; on a stalled job the reader decides whether to
// look again.
//
// DEC-221: the column is the Tier 2 scorecard. Under its heading ("PHÂN TÍCH AI · TIER 2", the case line at the right)
// a run that has a result is four score tiles over five tabs (`ResultPanel`); every other state, and the button that
// starts a run, is drawn in the same frame as it always was.
//
// Everything the model wrote (summary, narrative, hypotheses, quotes, next steps) is rendered as text.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";
import {
  getInvestigation,
  isInvestigationState,
  postAnalyze,
  statusOf,
  type InvestigationView,
  type RunView,
} from "../../api/tier2";
import { ApiError } from "../../api/client";
import { S } from "../../strings";
import { BUTTON, ERROR_TEXT, ErrorNotice, asText } from "./parts";
import { ResultPanel } from "./ResultPanel";
import { tier2Keys } from "./queryKeys";

/** How often a running analysis is asked about. */
export const POLL_MS = 3000;

/** The states a running job can end in. */
const ENDED: ReadonlySet<string> = new Set(["done", "failed", "stalled"]);

// The 409 details of `POST .../analyze` (tier2_runs.py), which the UI says in its own words.
const DETAIL_CONCLUDED = "case đã kết luận";
const DETAIL_RUNNING = "an investigation is already running for this case";

/** What to tell the reader when Phân tích is refused. */
function refusal(error: unknown): string {
  const status = statusOf(error);
  if (status === 429) return S.ai2.quotaExhausted;
  if (status === 404) return S.case.notFound;
  if (status === 409 && error instanceof ApiError) {
    const detail = error.detail;
    if (detail === DETAIL_CONCLUDED) return S.ai2.concluded;
    if (detail === DETAIL_RUNNING) return S.ai2.alreadyRunning;
    // A refusal this UI has no words for is shown as the server said it.
    if (typeof detail === "string" && detail !== "") return detail;
  }
  return S.common.unknownError;
}

/** What a 202 says before the server has been asked: a live job, with nothing of it to show yet. */
const runningView = (runId: string): InvestigationView => ({
  state: "running",
  run_id: runId,
  minutes: null,
  run: null,
  current: null,
  case_open: true,
});

export function InvestigationColumn({
  caseId,
  caseOpen,
  caseLine,
}: {
  caseId: string;
  caseOpen: boolean;
  /** "Case 0b30b853 · 3 cụm · lab-win-02", from the page that knows the case: drawn at the right of the heading. */
  caseLine?: string;
}) {
  const client = useQueryClient();
  // The run of the 202, kept here with the case it belongs to: a `done` view carries no top-level run_id, so
  // the poll needs it, and it is part of the query key. Another case has no run of this one.
  const [kept, setKept] = useState<{ caseId: string; runId: string } | null>(null);
  const runId = kept !== null && kept.caseId === caseId ? kept.runId : null;
  const key = tier2Keys.investigation(caseId, runId);
  const postingNow = useRef(false);
  const headingId = useId();

  const query = useQuery({
    queryKey: key,
    queryFn: async (): Promise<InvestigationView> => {
      // Every read names its run: the run of the 202, else the run the last answer named. A job with a run_id
      // and nothing behind it then answers "failed", never "idle".
      const before = client.getQueryData<InvestigationView>(key);
      const named = runId ?? before?.run_id ?? null;
      const next = await getInvestigation(caseId, named);
      // A state this UI does not know cannot be polled or acted on: it is an error, not a guess.
      if (!isInvestigationState(next.state)) throw new Error("unknown state");
      // The job writes last_analyzed_at and the timeline when it completes, so the case, and the list that
      // shows it, are read again when a live job ends, and only then: the answer before this one was
      // "running" (or "stalled", which is late and not over: the worker may still finish it, and the
      // reader's Kiểm tra lại then finds it done or failed), and a page that opens on a finished run has no
      // answer before it. A stalled answer after "running" counts as an end (the case is read once, as it
      // always was); one after "stalled" does not, it is the same wait.
      if (
        (before?.state === "running" && ENDED.has(next.state)) ||
        (before?.state === "stalled" && (next.state === "done" || next.state === "failed"))
      ) {
        void client.invalidateQueries({ queryKey: tier2Keys.case(caseId) });
        void client.invalidateQueries({ queryKey: tier2Keys.cases });
      }
      return next;
    },
    // An answer is fresh for one poll: the view a 202 seeds is not read again the moment it is shown.
    staleTime: POLL_MS,
    // Asked every 3 s while the job runs; on done, failed, stalled or an error nothing is asked, so the
    // reader's Kiểm tra lại and Thử lại are the only ways to ask again.
    refetchInterval: (polled) =>
      polled.state.status !== "error" && polled.state.data?.state === "running" ? POLL_MS : false,
  });
  const view = query.data ?? null;
  // The failure of the last read; the last good view stays under it.
  const error: unknown = query.isError ? query.error : null;

  const analyzeRun = useMutation({
    mutationFn: (id: string) => postAnalyze(id),
    onSuccess: (accepted, id) => {
      // What was read of this case before is stale now; none of it is read again here. The run of the 202
      // then gets its own key, seeded with a live job, so the previous result is hidden at once.
      void client.invalidateQueries({
        queryKey: tier2Keys.investigations(id),
        refetchType: "none",
      });
      client.setQueryData(
        tier2Keys.investigation(id, accepted.run_id),
        runningView(accepted.run_id),
      );
      setKept({ caseId: id, runId: accepted.run_id });
      // The case's own reads (and the list's) may name the run too.
      void client.invalidateQueries({ queryKey: tier2Keys.case(id) });
      void client.invalidateQueries({ queryKey: tier2Keys.cases });
    },
    onError: (failure, id) => {
      // Someone else's run is live: read it with no run named, so this column follows that one.
      if (statusOf(failure) !== 409) return;
      setKept((was) => (was !== null && was.caseId === id ? null : was));
      void client.invalidateQueries({ queryKey: tier2Keys.investigation(id, null) });
    },
  });
  // The reason Phân tích was refused; the next attempt clears it.
  const notice = analyzeRun.isError ? refusal(analyzeRun.error) : null;

  function analyze(): void {
    if (postingNow.current) return;
    postingNow.current = true;
    analyzeRun.mutate(caseId, {
      onSettled: () => {
        postingNow.current = false;
      },
    });
  }

  // The page knows the case is concluded before the server's last answer does, and the server may know
  // it before the page does: either one closes the column.
  const open = caseOpen && (view?.case_open ?? true);
  // A poll failed: the last view still says "running", but nothing polls it any more, so the error stands
  // in for it rather than a line that promises an answer is on the way.
  const pollFailed = error !== null && view?.state === "running";

  return (
    <section
      aria-labelledby={headingId}
      className="w-[560px] shrink-0 space-y-3.5 rounded border border-ai-border bg-ground p-4"
    >
      <div className="flex items-baseline justify-between gap-3">
        <h2 id={headingId} className="text-xs font-semibold tracking-[0.08em] text-ai-accent">
          {S.case.aiHeading}
        </h2>
        {caseLine !== undefined && caseLine !== "" && (
          <span className="min-w-0 text-right text-xs break-words text-muted">{caseLine}</span>
        )}
      </div>

      {error !== null && (
        <ErrorNotice
          message={statusOf(error) === 404 ? S.case.notFound : S.common.unknownError}
          // Asked with the run of the 202: a job with nothing behind it then answers "failed", not "idle".
          onRetry={() => void query.refetch()}
        />
      )}

      {view === null ? (
        error === null && <p role="status">{S.ai2.loading}</p>
      ) : pollFailed ? null : (
        <ViewBody
          view={view}
          open={open}
          posting={analyzeRun.isPending}
          onAnalyze={analyze}
          onRecheck={() => void query.refetch()}
        />
      )}

      {notice !== null && (
        <p role="alert" className={ERROR_TEXT}>
          {notice}
        </p>
      )}
    </section>
  );
}

function ViewBody({
  view,
  open,
  posting,
  onAnalyze,
  onRecheck,
}: {
  view: InvestigationView;
  open: boolean;
  posting: boolean;
  onAnalyze: () => void;
  onRecheck: () => void;
}) {
  const run = view.run;
  const hasResult = run !== null && run.result !== null && run.result !== undefined;
  const analyzeButton = open && (
    <button type="button" className={BUTTON} disabled={posting} onClick={onAnalyze}>
      {hasResult ? S.ai2.reanalyze : S.ai2.analyze}
    </button>
  );

  switch (view.state) {
    case "running":
      return <p role="status">{S.ai2.running}</p>;

    case "stalled":
      return (
        <div className="space-y-3">
          <p>{S.ai2.stalled(view.minutes ?? 0)}</p>
          <button type="button" className={BUTTON} onClick={onRecheck}>
            {S.ai2.recheck}
          </button>
        </div>
      );

    case "failed":
      return (
        <div className="space-y-3">
          <p className={ERROR_TEXT}>{open ? S.ai2.failed : S.ai2.failedClosed}</p>
          {analyzeButton}
          {run !== null &&
            (hasResult ? (
              <div className="space-y-2">
                <h3 className="text-sm font-semibold">{S.ai2.lastResult}</h3>
                <ResultPanel run={run} current={view.current} />
              </div>
            ) : (
              <div className="space-y-2">
                <h3 className="text-sm font-semibold">{S.ai2.lastResult}</h3>
                <Stopped run={run} open={open} />
              </div>
            ))}
        </div>
      );

    case "done":
      if (run === null) {
        return (
          <div className="space-y-3">
            <p>{open ? S.ai2.idle : S.ai2.idleClosed}</p>
            {analyzeButton}
          </div>
        );
      }
      return (
        <div className="space-y-3.5">
          {analyzeButton}
          {hasResult ? (
            <ResultPanel run={run} current={view.current} />
          ) : (
            <Stopped run={run} open={open} />
          )}
        </div>
      );

    case "idle":
      return (
        <div className="space-y-3">
          <p>{open ? S.ai2.idle : S.ai2.idleClosed}</p>
          {analyzeButton}
        </div>
      );
  }
}

/** Why a run has no result, in the server's words, and that the reader may try again while the case is open. */
function Stopped({ run, open }: { run: RunView; open: boolean }) {
  return (
    <p>
      {S.ai2.stopped(asText(run.stopped_text))}
      {open ? ` — ${S.ai2.retryable}` : ""}
    </p>
  );
}
