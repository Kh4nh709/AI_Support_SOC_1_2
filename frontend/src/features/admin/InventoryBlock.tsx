// "Kiểm kê tài sản" of the overview (P11-T11, spec §4.1): what the inventory holds now, and the reload that
// reads the three files again after a confirmation (`POST /api/admin/reload-inventory`, web/main.py).
//
// The answers, as AdminStates draws them:
//   - 200 `LoadReport`: the dialog closes and the block keeps the result (the counts, and the warnings the loader
//     raised) until it is dismissed or the next reload replaces it; the overview is read again
//     (`invalidateAfter("reloadInventory")`) and the counts follow when that read lands;
//   - 422, a list of texts, one for each fault of the files: the dialog closes and the block keeps the list and
//     says the database did not change (`load()` validates before it writes). Nothing is read again: nothing
//     changed;
//   - anything else (a 5xx, the network, a role that changed): the dialog stays and says it did not work.
//
// The files are loaded when the answer is in, so the dialog and the result never wait for the read that follows
// (up to about 30 s in the worst case): the mutation does not await it. The button that opened the dialog stays on
// the page, so the dialog gives the focus back to it. One latch (`useSubmitLatch`) keeps two clicks of one tick to
// one POST: the confirm button is `disabled` a render late.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import {
  adminErrorOf,
  reloadInventory,
  type LoadReport,
  type OverviewResponse,
} from "../../api/admin";
import { formatTime } from "../../format";
import { S } from "../../strings";
import { ConfirmDialog } from "./ConfirmDialog";
import { invalidateAfter } from "./adminKeys";
import { BlockError, OUTLINE_BUTTON, Panel } from "./OverviewBlocks";
import { writeErrorText, type SectionFailure } from "./overviewModel";
import { useSubmitLatch } from "./useSubmitLatch";

const P = S.admin.overviewPage;
const I = P.inventory;

/** The prefix `enrichment/inventory.py` puts on a warning (`WARNING`); under "N cảnh báo" it says nothing more. */
const WARNING_PREFIX = "warning: ";
const withoutPrefix = (text: string): string =>
  text.startsWith(WARNING_PREFIX) ? text.slice(WARNING_PREFIX.length) : text;

/** The files the loader reads, in the order of the canvas's dialog. */
const FILES = ["inventory.yaml", "identities.yaml", "iocs.csv"] as const;

type Result = { kind: "loaded"; report: LoadReport } | { kind: "refused"; messages: string[] };

const MONO_LIST = "list-inside list-disc space-y-1 font-mono text-xs break-words";

export function InventoryBlock({
  inventory,
  failure,
  onRetryRead,
}: {
  /** `null` when the section failed. */
  inventory: OverviewResponse["inventory"];
  failure: SectionFailure | null;
  /** Asks the server for the overview again (the block's own "Thử lại"). */
  onRetryRead: () => void;
}) {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [result, setResult] = useState<Result | null>(null);

  const reload = useMutation({
    mutationFn: () => reloadInventory(),
    onSuccess: (report) => {
      setOpen(false);
      setResult({ kind: "loaded", report });
      // Not awaited: the files are loaded, and the dialog and the result must not wait for the read.
      void invalidateAfter(client, "reloadInventory");
    },
    onError: (thrown) => {
      const error = adminErrorOf(thrown);
      if (error.kind === "messages" || error.kind === "message") {
        setOpen(false);
        setResult({
          kind: "refused",
          messages: error.kind === "messages" ? error.messages : [error.message],
        });
      } else {
        setDialogError(writeErrorText(error));
      }
    },
  });
  const runReload = useSubmitLatch(reload);

  return (
    <>
      <Panel title={I.title}>
        {failure !== null || inventory === null ? (
          <BlockError failure={failure ?? "unknown"} onRetry={onRetryRead} />
        ) : (
          <dl className="flex flex-col gap-2 text-[13px]">
            <Line label={I.assets}>{inventory.assets}</Line>
            <Line label={I.identities}>{inventory.identities}</Line>
            <Line label={I.iocs}>{inventory.iocs}</Line>
            <Line label={I.loadedAt}>
              {inventory.loaded_at === null ? I.neverLoaded : formatTime(inventory.loaded_at)}
            </Line>
          </dl>
        )}

        {result?.kind === "loaded" && (
          <div
            role="status"
            className="flex flex-col gap-2 rounded-lg border border-console-success-outline bg-console-success-tint px-3.5 py-3 text-[13.5px] text-console-success-text"
          >
            <div className="flex items-start gap-3">
              <p className="grow">
                {I.loaded(
                  result.report.assets,
                  result.report.identities,
                  result.report.iocs,
                  result.report.deactivated,
                )}
              </p>
              <Dismiss onClick={() => setResult(null)} />
            </div>
            {result.report.warnings.length > 0 && (
              <>
                <p className="text-[13px] text-console-secondary">
                  {I.warnings(result.report.warnings.length)}
                </p>
                <ul className={`${MONO_LIST} text-console-warning-text`}>
                  {result.report.warnings.map((warning, i) => (
                    <li key={`${i}:${warning}`}>{withoutPrefix(warning)}</li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
        {result?.kind === "refused" && (
          <div
            role="alert"
            className="flex flex-col gap-2 rounded-lg border border-console-danger-outline bg-critical-bg px-3.5 py-3 text-[13px] leading-snug text-console-danger-text"
          >
            <div className="flex items-start gap-3">
              <p className="grow">{I.refused}</p>
              <Dismiss onClick={() => setResult(null)} />
            </div>
            <ul className={MONO_LIST}>
              {result.messages.map((message, i) => (
                <li key={`${i}:${message}`}>{message}</li>
              ))}
            </ul>
          </div>
        )}

        <button
          type="button"
          onClick={() => {
            setDialogError(null);
            setOpen(true);
          }}
          className="mt-auto h-11 rounded-lg border border-console-outline text-sm font-semibold hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text"
        >
          {I.reload}
        </button>
        <p className="text-xs leading-normal text-muted">{I.hint}</p>
      </Panel>

      {open && (
        <ConfirmDialog
          title={I.dialogTitle}
          confirmLabel={I.confirm}
          busy={reload.isPending}
          error={dialogError}
          onConfirm={() => {
            setDialogError(null);
            runReload();
          }}
          onCancel={() => {
            setOpen(false);
            setDialogError(null);
          }}
        >
          <p>
            {I.dialogRead} <File name={FILES[0]} />, <File name={FILES[1]} /> {I.dialogAnd}{" "}
            <File name={FILES[2]} />
            {I.dialogRest}
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}

/** One line of the block: a label at the left and its number or time at the right. */
function Line({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-2.5">
      <dt className="text-console-secondary">{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function Dismiss({ onClick }: { onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} className={`${OUTLINE_BUTTON} shrink-0 text-text`}>
      {S.common.close}
    </button>
  );
}

function File({ name }: { name: string }) {
  return <span className="font-mono text-[12.5px]">{name}</span>;
}
