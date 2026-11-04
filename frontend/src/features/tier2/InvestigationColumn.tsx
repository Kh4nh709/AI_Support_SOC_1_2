// The ② column of the case page (spec §4): what the case assistant made of the case. It reads the state
// from the server (TanStack Query owns the read), starts an analysis on Phân tích, and polls every 3 s
// while one is running. It stops on done, failed or stalled; on a stalled job the reader decides whether to
// look again.
//
// Everything the model wrote (summary, narrative, hypotheses, quotes, next steps) is rendered as text.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState } from "react";
import {
  HELD_CONCLUSION,
  MODEL_CONCLUSIONS,
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
import { ragNoteOf } from "../../api/rag";
import { RagNotice } from "../../components/RagNotice";
import { formatDateTime, formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { BUTTON, ERROR_TEXT, ErrorNotice, HEADING, asText } from "./parts";
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

export function InvestigationColumn({ caseId, caseOpen }: { caseId: string; caseOpen: boolean }) {
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
      className="w-[560px] shrink-0 space-y-4 rounded border border-ai-border bg-ai-surface p-4"
    >
      <h2 id={headingId} className="text-sm font-semibold tracking-wide text-ai-accent">
        {S.case.aiHeading}
      </h2>

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
              <RunResult run={run} current={view.current} title={S.ai2.lastResult} />
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
        <div className="space-y-4">
          {analyzeButton}
          {hasResult ? (
            <RunResult run={run} current={view.current} title={null} />
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

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <h3 className={HEADING}>{title}</h3>
      {children}
    </div>
  );
}

/**
 * What the AI concluded on the case (P14-T03, DEC-213): "AI kết luận: <the label of ②'s conclusion>", and when the
 * system held it as `need_more_data`, "… — hệ thống giữ lại vì: <causes>" (just "… — hệ thống giữ lại" when it
 * knows no cause). The conclusion is the model's own (`model_conclusion`), not the `need_more_data` the system
 * stored in its place; a cause the UI has no label for is shown as its code. All of it is text.
 *
 * P14-T07 (DEC-213, spec 4.3): `pct` is how strongly the case matched approved knowledge (the run's `rag.best_pct`,
 * null when there was no match): "AI kết luận: <label> — trùng 87% với tri thức đã duyệt", before the system's own
 * clause, as on the alert page.
 */
function ModelConclusion({
  conclusion,
  causes,
  held,
  pct,
}: {
  conclusion: string;
  causes: string[];
  held: boolean;
  pct: number | null;
}) {
  return (
    <p className="text-base">
      {S.ai2.conclusion}: <strong>{labelOf(S.ai2.suggestedConclusion, conclusion)}</strong>
      {pct !== null && ` ${S.rag.dash} ${S.rag.match(pct)}`}
      {held && ` ${S.ai2.heldLine(causes.map((cause) => labelOf(S.ai2.heldReason, cause)))}`}
    </p>
  );
}

export function RunResult({
  run,
  current,
  title,
}: {
  run: RunView;
  current: InvestigationView["current"];
  title: string | null;
}) {
  const evidenceId = useId();
  // A run from before P14-T02 carries no `model_conclusion`: it keeps the stored label and the overruled text.
  const modelConclusion =
    typeof run.model_conclusion === "string" && run.model_conclusion !== ""
      ? run.model_conclusion
      : null;
  // The causes the server named. The system held the conclusion when it named one, and also when the stored
  // conclusion is `need_more_data` over one of the three the model may give (M5): the stored word is the
  // system's own, so a `held_by` that came out empty does not turn the override into the model's answer.
  const causes = (Array.isArray(run.held_by) ? run.held_by : []).filter(
    (cause): cause is string => typeof cause === "string" && cause !== "",
  );
  const held =
    modelConclusion !== null &&
    (causes.length > 0 ||
      (run.conclusion === HELD_CONCLUSION &&
        (MODEL_CONCLUSIONS as readonly string[]).includes(modelConclusion)));
  // The percentage and the notice (P14-T07) are the run's own, read through `ragNoteOf`.
  const rag = ragNoteOf(run.rag);
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
        {modelConclusion !== null ? (
          <ModelConclusion conclusion={modelConclusion} causes={causes} held={held} pct={rag.pct} />
        ) : (
          <p className="flex flex-wrap items-baseline gap-2">
            <strong className="text-base">{asText(run.conclusion_label)}</strong>
            <code className="text-xs text-muted">{asText(run.conclusion)}</code>
          </p>
        )}
        <p className="text-sm">
          {`${S.ai2.confidence}: ${labelOf(S.ai2.confidenceLevel, run.confidence)}`}
        </p>
        {rag.notApplied !== null && <RagNotice kind={rag.notApplied} subject="case" />}
      </Block>

      {(modelConclusion === null || (held && causes.length === 0)) &&
        run.overruled !== null &&
        run.overruled !== undefined &&
        run.overruled !== "" && (
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

      {run.playbook_used !== null &&
        run.playbook_used !== undefined &&
        run.playbook_used !== "" && (
          <p className="text-xs text-muted">{S.ai2.playbook(asText(run.playbook_used))}</p>
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
