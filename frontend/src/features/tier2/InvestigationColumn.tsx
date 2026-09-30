// The ② column of the case page (spec §4): what the case assistant made of the case. It reads the state
// from the server, starts an analysis on Phân tích, and polls every 3 s while one is running. It stops on
// done, failed or stalled; on a stalled job the reader decides whether to look again.
//
// Everything the model wrote (summary, narrative, hypotheses, quotes, next steps) is rendered as text.
import { useCallback, useEffect, useId, useRef, useState } from "react";
import {
  getInvestigation,
  isInvestigationState,
  postAnalyze,
  statusOf,
  type EvidenceRow,
  type HypothesisRow,
  type InvestigationView,
  type RunView,
} from "../../api/tier2";
import { ApiError } from "../../api/client";
import { formatDateTime, formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { BUTTON, ERROR_TEXT, ErrorNotice, HEADING, asText } from "./parts";

/** How often a running analysis is asked about. */
export const POLL_MS = 3000;

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

export function InvestigationColumn({ caseId, caseOpen }: { caseId: string; caseOpen: boolean }) {
  const [view, setView] = useState<InvestigationView | null>(null);
  // The run of the 202, kept here: a `done` view carries no top-level run_id, and every poll names its run.
  const [runId, setRunId] = useState<string | null>(null);
  // The failure of the last read; the polling stops on it.
  const [error, setError] = useState<unknown>(null);
  // The reason Phân tích was refused.
  const [notice, setNotice] = useState<string | null>(null);
  const [posting, setPosting] = useState(false);
  const postingNow = useRef(false);
  // Only the newest read counts: a read that answers after a newer one was made is dropped.
  const latest = useRef(0);
  const headingId = useId();

  const read = useCallback(
    (id: string | null): Promise<void> => {
      latest.current += 1;
      const mine = latest.current;
      return getInvestigation(caseId, id).then(
        (next) => {
          if (latest.current !== mine) return;
          // A state this UI does not know cannot be polled or acted on: it is an error, not a guess.
          if (!isInvestigationState(next.state)) {
            setError(new Error("unknown state"));
            return;
          }
          setView(next);
          setError(null);
          if (next.run_id !== null && next.run_id !== undefined) setRunId(next.run_id);
        },
        (failure: unknown) => {
          if (latest.current === mine) setError(failure);
        },
      );
    },
    [caseId],
  );

  useEffect(() => {
    void read(null);
  }, [read]);

  const polling = view?.state === "running" && error === null;
  const pollId = runId ?? view?.run_id ?? null;

  useEffect(() => {
    if (!polling) return;
    let asking = false;
    const timer = setInterval(() => {
      // A poll still unanswered is not asked again.
      if (asking) return;
      asking = true;
      void read(pollId).finally(() => {
        asking = false;
      });
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [polling, pollId, read]);

  async function analyze(): Promise<void> {
    if (postingNow.current) return;
    postingNow.current = true;
    setPosting(true);
    setNotice(null);
    try {
      const accepted = await postAnalyze(caseId);
      // A read that was in flight predates this run.
      latest.current += 1;
      setRunId(accepted.run_id);
      setError(null);
      // A live job hides the previous result.
      setView({
        state: "running",
        run_id: accepted.run_id,
        minutes: null,
        run: null,
        current: null,
        case_open: true,
      });
    } catch (failure) {
      setNotice(refusal(failure));
      // Someone else's run is live: read it, so this column follows that one.
      if (statusOf(failure) === 409) void read(null);
    } finally {
      postingNow.current = false;
      setPosting(false);
    }
  }

  // The page knows the case is concluded before the server's last answer does, and the server may know
  // it before the page does: either one closes the column.
  const open = caseOpen && (view?.case_open ?? true);

  return (
    <section
      aria-labelledby={headingId}
      className="w-[560px] shrink-0 space-y-4 rounded border border-ai-border bg-ai-surface p-4"
    >
      <h2 id={headingId} className="text-sm font-semibold tracking-wide text-ai-accent">
        {S.case.aiHeading}
      </h2>

      {error !== null && (
        <ErrorNotice
          message={statusOf(error) === 404 ? S.case.notFound : S.common.unknownError}
          onRetry={() => void read(null)}
        />
      )}

      {view === null ? (
        error === null && <p role="status">{S.ai2.loading}</p>
      ) : (
        <ViewBody
          view={view}
          open={open}
          posting={posting}
          onAnalyze={() => void analyze()}
          onRecheck={() => void read(runId ?? view.run_id)}
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
          {hasResult && <RunResult run={run} current={view.current} title={S.ai2.lastResult} />}
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
        <div className="space-y-4">
          {analyzeButton}
          {hasResult ? (
            <RunResult run={run} current={view.current} title={null} />
          ) : (
            <p>
              {S.ai2.stopped(asText(run.stopped_text))}
              {open ? ` — ${S.ai2.retryable}` : ""}
            </p>
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

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <h3 className={HEADING}>{title}</h3>
      {children}
    </div>
  );
}

function RunResult({
  run,
  current,
  title,
}: {
  run: RunView;
  current: InvestigationView["current"];
  title: string | null;
}) {
  const evidenceId = useId();
  const hypotheses = run.hypotheses ?? [];
  const evidence = run.evidence ?? [];
  const nextSteps = run.next_steps ?? [];
  return (
    <div className="space-y-4">
      {title !== null && <h3 className="text-sm font-semibold">{title}</h3>}
      <p className="text-xs text-muted">{S.ai2.resultAt(formatDateTime(run.created_at))}</p>

      {run.changed === true && (
        <div className="space-y-1 rounded border border-medium/40 bg-medium-bg p-3 text-sm text-medium">
          <p>{S.ai2.stale}</p>
          {run.snapshot !== null && run.snapshot !== undefined && (
            <p>
              {S.ai2.snapshot(
                run.snapshot.alert_count,
                run.snapshot.total_occurrences,
                run.snapshot.last_seen_at === null ? null : formatTime(run.snapshot.last_seen_at),
              )}
            </p>
          )}
          {current !== null && (
            <p>
              {S.ai2.current(
                current.alert_count,
                current.total_occurrences,
                current.last_seen_at === null ? null : formatTime(current.last_seen_at),
              )}
            </p>
          )}
        </div>
      )}

      <Block title={S.ai2.suggested}>
        <p className="flex flex-wrap items-baseline gap-2">
          <strong className="text-base">{asText(run.conclusion_label)}</strong>
          <code className="text-xs text-muted">{asText(run.conclusion)}</code>
        </p>
        <p className="text-sm">
          {`${S.ai2.confidence}: ${labelOf(S.ai2.confidenceLevel, run.confidence)}`}
        </p>
      </Block>

      {run.overruled !== null && run.overruled !== undefined && run.overruled !== "" && (
        <p className="rounded border border-high/40 bg-high-bg p-3 text-sm text-high">
          {run.overruled}
        </p>
      )}

      <Block title={S.ai2.summary}>
        <p className="whitespace-pre-wrap text-sm">{asText(run.summary)}</p>
      </Block>

      <Block title={S.ai2.narrative}>
        <p className="whitespace-pre-wrap text-sm">{asText(run.narrative)}</p>
      </Block>

      {hypotheses.length > 0 && (
        <Block title={S.ai2.hypotheses}>
          <ol className="space-y-3">
            {hypotheses.map((hypothesis, index) => (
              <Hypothesis key={index} hypothesis={hypothesis} />
            ))}
          </ol>
        </Block>
      )}

      <div className="space-y-1">
        <h3 id={evidenceId} className={HEADING}>
          {S.ai2.evidence}
        </h3>
        {evidence.length === 0 ? (
          <p className="text-sm">{S.ai2.noEvidence}</p>
        ) : (
          <ul aria-labelledby={evidenceId} className="space-y-2">
            {evidence.map((row, index) => (
              <EvidenceItem key={index} row={row} />
            ))}
          </ul>
        )}
      </div>

      {nextSteps.length > 0 && (
        <Block title={S.ai2.nextSteps}>
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {nextSteps.map((step, index) => (
              <li key={index}>{asText(step)}</li>
            ))}
          </ul>
        </Block>
      )}

      <p className="text-xs text-muted">{S.ai2.disclaimer}</p>
    </div>
  );
}

/** One hypothesis, with the evidence for it and against it. One with none against is flagged. */
function Hypothesis({ hypothesis }: { hypothesis: HypothesisRow }) {
  const forId = useId();
  const againstId = useId();
  const supporting = hypothesis.evidence_for ?? [];
  const counter = hypothesis.evidence_against ?? [];
  return (
    <li className="space-y-2 rounded border border-ai-border p-3 text-sm">
      <p className="font-medium">{asText(hypothesis.text)}</p>
      <div>
        <p id={forId} className="text-xs text-muted">
          {S.ai2.supporting}
        </p>
        <ul aria-labelledby={forId} className="list-disc pl-5">
          {supporting.map((line, index) => (
            <li key={index}>{asText(line)}</li>
          ))}
        </ul>
      </div>
      {counter.length === 0 ? (
        <p className="rounded bg-medium-bg p-2 text-xs text-medium">{S.ai2.noCounterEvidence}</p>
      ) : (
        <div>
          <p id={againstId} className="text-xs text-muted">
            {S.ai2.counter}
          </p>
          <ul aria-labelledby={againstId} className="list-disc pl-5">
            {counter.map((line, index) => (
              <li key={index}>{asText(line)}</li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

/** One quote the assistant cited, marked verified only when the server checked it against the log. */
function EvidenceItem({ row }: { row: EvidenceRow }) {
  const verified = row.verified === true;
  return (
    <li className="space-y-1 rounded border border-ai-border p-3 text-sm">
      <div className="flex items-center gap-2">
        <span
          data-verified={verified}
          className={
            verified
              ? "rounded bg-low-bg px-2 py-0.5 text-xs text-low"
              : "rounded bg-medium-bg px-2 py-0.5 text-xs text-medium"
          }
        >
          {verified ? S.ai2.mark.verified : S.ai2.unverified}
        </span>
        <code className="text-xs text-muted">{asText(row.alert_id)}</code>
      </div>
      <p className="whitespace-pre-wrap font-mono text-xs">{`“${asText(row.quote)}”`}</p>
      <p>{asText(row.why)}</p>
      {!verified && <p className="text-xs text-medium">{asText(row.reason_text)}</p>}
    </li>
  );
}
