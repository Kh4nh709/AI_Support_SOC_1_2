// "Job lỗi" of the overview (P11-T11, spec §4.1 and §5.4): the failed jobs, and the retry that puts one back
// in the worker's queue after a confirmation.
//
// What each answer of `POST /api/admin/jobs/{id}/retry` does (AdminStates):
//   - 200: the dialog closes and a toast says it, in the block; the overview is read again
//     (`invalidateAfter("retryJob")`) and the retried job leaves the list when that read lands;
//   - 409 `not_failed` and 404 `not_found`: the list on screen is stale (another admin or the worker got there
//     first), so the dialog closes, the block says why, and the list is read again;
//   - 409 `already_queued`: the list is right and the job still failed, so the dialog stays and says why;
//   - anything else (a 5xx, the network, a role that changed): the dialog stays and says it did not work.
//
// The write has committed when the answer is in, so the dialog and the notice never wait for the read that
// follows (nine sections, up to about 30 s in the worst case): the mutation does not await it, which also frees
// its busy state and its latch for the next job at once.
//
// Focus. The button that opened the dialog is in the row of the job, and on the three answers above that row
// leaves the list when the new read lands, so the focus the dialog gives back would be lost to `<body>`. The
// block sends the focus to its own heading when it closes the dialog (an effect after the commit that
// unmounts it, so the dialog's give-back cannot undo it); the heading stays whatever the list does.
//
// One latch (`useSubmitLatch`) keeps two clicks of one tick to one POST: the confirm button is `disabled` a
// render late.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { adminErrorOf, retryJob, type FailedJob } from "../../api/admin";
import { type Column, DataTable } from "../../components/DataTable";
import { Toast } from "../../components/Toast";
import { formatTime } from "../../format";
import { S } from "../../strings";
import { ConfirmDialog } from "./ConfirmDialog";
import { invalidateAfter } from "./adminKeys";
import { BlockError, Mark, OUTLINE_BUTTON, Panel } from "./OverviewBlocks";
import { useSubmitLatch } from "./useSubmitLatch";
import {
  FAILED_JOBS_CAP,
  lastAttemptAt,
  writeErrorText,
  type SectionFailure,
} from "./overviewModel";

const J = S.admin.overviewPage.jobs;

const COLUMNS: Column<FailedJob>[] = [
  {
    id: "job",
    header: J.job,
    cell: (job) => <span className="font-mono">{job.job_id}</span>,
  },
  { id: "type", header: J.type, cell: (job) => <span className="font-mono">{job.job_type}</span> },
  {
    id: "subject",
    header: J.subject,
    cell: (job) => <span className="break-words font-mono text-[12.5px]">{job.subject_id}</span>,
  },
  {
    id: "attempts",
    header: J.attempts,
    className: "whitespace-nowrap text-right",
    cell: (job) => job.attempts,
  },
  {
    id: "error",
    header: J.lastError,
    cell: (job) => (
      <span className="break-words font-mono text-xs text-[#fda4af]">
        {job.last_error ?? S.common.missing}
      </span>
    ),
  },
  {
    id: "at",
    header: J.at,
    className: "whitespace-nowrap text-[#aeb9c6]",
    cell: (job) => formatTime(lastAttemptAt(job)),
  },
];

export function FailedJobsBlock({
  jobs,
  failure,
  onRetryRead,
}: {
  /** `null` when the section failed. */
  jobs: FailedJob[] | null;
  failure: SectionFailure | null;
  /** Asks the server for the overview again (the block's own "Thử lại"). */
  onRetryRead: () => void;
}) {
  const client = useQueryClient();
  const [pending, setPending] = useState<FailedJob | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  // The block's heading, and a counter of the requests to focus it: each one is a new value, so each renders and
  // runs the effect, even when nothing else on the screen changed.
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [focusAsk, setFocusAsk] = useState(0);

  // Runs in the commit that closes the dialog, after the dialog's own cleanup (which gives the focus back to the
  // button that opened it), so it cannot be undone by it.
  useEffect(() => {
    if (focusAsk > 0) headingRef.current?.focus();
  }, [focusAsk]);

  /** The write is over and the list on screen is about to change: close the dialog, then read the list again. */
  function closeAndReload() {
    setFocusAsk((n) => n + 1);
    setPending(null);
    // Not awaited: the write has committed, and the dialog and the notice must not wait for the read.
    void invalidateAfter(client, "retryJob");
  }

  const retry = useMutation({
    mutationFn: (jobId: number) => retryJob(jobId),
    onSuccess: (_answer, jobId) => {
      setToast(J.done(jobId));
      closeAndReload();
    },
    onError: (thrown) => {
      const error = adminErrorOf(thrown);
      if (
        error.kind === "reason" &&
        (error.reason === "not_failed" || error.reason === "not_found")
      ) {
        setNotice(S.admin.reason[error.reason]);
        closeAndReload();
      } else {
        setDialogError(writeErrorText(error));
      }
    },
  });
  const runRetry = useSubmitLatch(retry);

  function open(job: FailedJob) {
    setNotice(null);
    setDialogError(null);
    setPending(job);
  }

  const count =
    jobs === null || jobs.length === 0
      ? null
      : jobs.length >= FAILED_JOBS_CAP
        ? J.countCapped(jobs.length)
        : J.count(jobs.length);

  const columns: Column<FailedJob>[] = [
    ...COLUMNS,
    {
      id: "actions",
      header: <span className="sr-only">{J.actions}</span>,
      className: "whitespace-nowrap text-right",
      cell: (job) => (
        <button
          type="button"
          aria-label={J.retryJob(job.job_id)}
          onClick={() => open(job)}
          className={OUTLINE_BUTTON}
        >
          {J.retry}
        </button>
      ),
    },
  ];

  return (
    <>
      <Panel
        title={J.title}
        className="col-span-2"
        headingRef={headingRef}
        aside={count === null ? undefined : <Mark tone="warn">{count}</Mark>}
      >
        {toast !== null && <Toast onClose={() => setToast(null)}>{toast}</Toast>}
        {notice !== null && (
          <div
            role="alert"
            className="flex items-start gap-3 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-3 text-[13.5px] leading-snug text-[#fcd9a8]"
          >
            <span className="grow">{notice}</span>
            <button type="button" onClick={() => setNotice(null)} className={OUTLINE_BUTTON}>
              {S.common.close}
            </button>
          </div>
        )}

        {failure !== null || jobs === null ? (
          <BlockError failure={failure ?? "unknown"} onRetry={onRetryRead} />
        ) : jobs.length === 0 ? (
          <p className="flex items-center gap-2.5 text-[13.5px] text-[#9ff0c5]">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M4 12l5 5L20 6" />
            </svg>
            <span>{J.empty}</span>
          </p>
        ) : (
          <>
            <DataTable
              label={J.table}
              columns={columns}
              rows={jobs}
              rowKey={(job) => String(job.job_id)}
            />
            <p className="text-xs text-muted">{J.note}</p>
          </>
        )}
      </Panel>

      {pending !== null && (
        <ConfirmDialog
          title={J.dialogTitle(pending.job_id)}
          confirmLabel={J.retry}
          busy={retry.isPending}
          error={dialogError}
          onConfirm={() => {
            setDialogError(null);
            runRetry(pending.job_id);
          }}
          onCancel={() => {
            setPending(null);
            setDialogError(null);
          }}
        >
          <dl className="flex flex-col gap-1.5 text-[13px]">
            <Row label={J.type}>
              <span className="font-mono">{pending.job_type}</span>
            </Row>
            <Row label={J.subject}>
              <span className="break-all font-mono">{pending.subject_id}</span>
            </Row>
            <Row label={J.attempts}>{J.times(pending.attempts)}</Row>
            <Row label={J.lastError}>
              <span className="break-words font-mono text-xs">
                {pending.last_error ?? S.common.missing}
              </span>
            </Row>
          </dl>
          <p className="text-[12.5px] leading-normal text-[#aeb9c6]">{J.dialogNote}</p>
        </ConfirmDialog>
      )}
    </>
  );
}

/** One line of the dialog: a label at the left and its value. */
function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[110px_minmax(0,1fr)] gap-x-3">
      <dt className="text-muted">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}
