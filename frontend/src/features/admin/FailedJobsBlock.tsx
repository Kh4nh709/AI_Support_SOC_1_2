// "Job lỗi" of the overview (P11-T11, spec §4.1 and §5.4): the failed jobs, and the retry that puts one back
// in the worker's queue after a confirmation.
//
// What each answer of `POST /api/admin/jobs/{id}/retry` does (AdminStates):
//   - 200: the dialog closes, the overview is read again (`invalidateAfter("retryJob")`), a toast says it;
//   - 409 `not_failed` and 404 `not_found`: the list on screen is stale (another admin or the worker got there
//     first), so the dialog closes, the list is read again, and the block says why, in the block;
//   - 409 `already_queued`: the list is right and the job still failed, so the dialog stays and says why;
//   - anything else (a 5xx, the network, a role that changed): the dialog stays and says it did not work.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { adminErrorOf, retryJob, type FailedJob } from "../../api/admin";
import { type Column, DataTable } from "../../components/DataTable";
import { Toast } from "../../components/Toast";
import { formatTime } from "../../format";
import { S } from "../../strings";
import { ConfirmDialog } from "./ConfirmDialog";
import { invalidateAfter } from "./adminKeys";
import { BlockError, Mark, OUTLINE_BUTTON, Panel } from "./OverviewBlocks";
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

  const retry = useMutation({
    mutationFn: (jobId: number) => retryJob(jobId),
    onSuccess: async (_answer, jobId) => {
      await invalidateAfter(client, "retryJob");
      setPending(null);
      setToast(J.done(jobId));
    },
    onError: async (thrown) => {
      const error = adminErrorOf(thrown);
      if (
        error.kind === "reason" &&
        (error.reason === "not_failed" || error.reason === "not_found")
      ) {
        await invalidateAfter(client, "retryJob");
        setPending(null);
        setNotice(S.admin.reason[error.reason]);
      } else {
        setDialogError(writeErrorText(error));
      }
    },
  });

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
        aside={count === null ? undefined : <Mark tone="warn">{count}</Mark>}
      >
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
            retry.mutate(pending.job_id);
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

      {toast !== null && (
        <div className="fixed bottom-6 right-6 z-40 w-96">
          <Toast onClose={() => setToast(null)}>{toast}</Toast>
        </div>
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
