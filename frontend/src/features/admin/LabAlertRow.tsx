// One alert of a lab run, and the three buttons that label it (P14-T10, DEC-213, spec §6).
//
// BLIND (DEC-101). The server sends the alert's own fields and its label (`ITEM_KEYS` of lab/labels.py through the
// labelling filter); this file is the second wall. It renders each allowed field BY NAME and nothing else: no loop
// over the keys of the alert, no dump of it, no spread, so a key the server should never send has no way onto the
// page (LabRunPage.test.tsx plants some, and reads this file with a checker). It links to nothing: an alert page or a
// case page would show what was decided.
//
// A write goes to the server first, and the row changes when the server has said yes: no optimistic update, so the
// row never shows a label the server does not hold. The row is told through `onLabelled`, which moves the counter of
// the page (and, as the write's last step, makes sure no read of the run that was already out can undo it: the row's
// write is not over until `onLabelled` has answered). A button the click would change nothing with (the label the alert
// already has, `Bỏ nhãn` of an alert with none) is `aria-disabled` and sends nothing; it is not `disabled`, so the
// focus stays where the admin put it.
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import {
  deleteLabLabel,
  labErrorOf,
  putLabLabel,
  type LabAlert,
  type LabLabel,
} from "../../api/admin";
import { LogBlock } from "../../components/LogBlock";
import { formatDateTime } from "../../format";
import { S } from "../../strings";
import { labRowErrorText } from "./labModel";
import { useSubmitLatch } from "./useSubmitLatch";

const R = S.admin.lab.runPage;

const MONO = "font-mono";
const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";
const BUTTON = `h-[34px] whitespace-nowrap rounded-md border px-3 text-[13px] ${FOCUS} aria-disabled:cursor-not-allowed aria-disabled:opacity-50`;
// Whole class names, written out: Tailwind finds a class by reading the source.
const IDLE = "border-[#2e3a48] text-[#c9d3df] hover:bg-ground";
const PRESSED: Record<LabLabel, string> = {
  true_positive: "border-[#7a2e38] bg-[#3a1217] font-semibold text-[#fda4af]",
  false_positive: "border-[#1f6b49] bg-[#133528] font-semibold text-[#9ff0c5]",
};
const CHIP: Record<LabLabel | "none", string> = {
  true_positive: "bg-[#3a1217] text-[#fda4af]",
  false_positive: "bg-[#133528] text-[#9ff0c5]",
  none: "bg-[#1c2530] text-[#8fa0b3]",
};

/** A field that came empty is a dash, never a blank and never the word "null". */
function orDash(value: string | number | null): string {
  return value === null || value === "" ? S.common.missing : String(value);
}

export function LabAlertRow({
  alert,
  onLabelled,
}: {
  alert: LabAlert;
  /**
   * The server has set (or, with null, cleared) the label of this alert: the page moves its counter. The row's write
   * lasts until it has answered.
   */
  onLabelled: (alertId: string, label: LabLabel | null) => void | Promise<void>;
}) {
  const [error, setError] = useState<string | null>(null);
  // The details are rendered when they are opened: a raw log is up to 32 KB, and a run holds a hundred rows a page.
  const [open, setOpen] = useState(false);

  const mutation = useMutation({
    mutationFn: async (label: LabLabel | null): Promise<void> => {
      if (label === null) await deleteLabLabel(alert.alert_id);
      else await putLabLabel(alert.alert_id, label);
    },
    onMutate: () => setError(null),
    onSuccess: async (_answer, label) => {
      await onLabelled(alert.alert_id, label);
    },
    onError: (failure) => setError(labRowErrorText(labErrorOf(failure))),
  });
  // One write at a time on a row, even for two presses in one tick (see useSubmitLatch.ts).
  const run = useSubmitLatch(mutation);

  const choose = (label: LabLabel) => {
    if (label !== alert.label) run(label);
  };
  const clear = () => {
    if (alert.label !== null) run(null);
  };

  const state = alert.label ?? "none";
  const stateText = alert.label === null ? S.admin.lab.label.none : S.admin.lab.label[alert.label];

  return (
    <li
      aria-label={R.alertLabel(alert.alert_id)}
      aria-busy={mutation.isPending || undefined}
      className="space-y-2.5 rounded-[10px] border border-border bg-surface px-4 py-3.5"
    >
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[13.5px]">
        <span className={`${MONO} text-xs text-muted`}>{alert.alert_id}</span>
        <span>
          <span className="text-muted">{R.received}</span> {formatDateTime(alert.received_at)}
        </span>
        <span className="text-[#aeb9c6]">
          {R.rule} <span className={`${MONO} text-text`}>{orDash(alert.rule_id)}</span>{" "}
          <span>{R.level(alert.rule_level)}</span>
        </span>
        <span className="text-[#aeb9c6]">
          {R.agent}{" "}
          <span className={`${MONO} break-words text-text`}>{orDash(alert.agent_name)}</span>
        </span>
        <span className={`${MONO} break-words text-[#aeb9c6]`}>
          {`${orDash(alert.srcip)} → ${orDash(alert.dstip)}`}
        </span>
        <span
          className={`ml-auto inline-block rounded px-2 py-0.5 text-xs font-semibold ${CHIP[state]}`}
        >
          {stateText}
        </span>
      </div>

      <p className="text-[14px] break-words">{orDash(alert.description)}</p>

      <details onToggle={(event) => setOpen(event.currentTarget.open)}>
        <summary className={`cursor-pointer text-[13px] text-[#aeb9c6] hover:text-text ${FOCUS}`}>
          {R.details}
        </summary>
        {open && (
          <div className="mt-2.5 space-y-3">
            <dl className="grid grid-cols-[170px_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-[13px]">
              <dt className="text-muted">{R.detail.alertTime}</dt>
              <dd>{formatDateTime(alert.alert_time)}</dd>
              <dt className="text-muted">{R.detail.user}</dt>
              <dd className={`${MONO} break-words`}>{orDash(alert.alert_user)}</dd>
              <dt className="text-muted">{R.detail.category}</dt>
              <dd className="break-words">{orDash(alert.category)}</dd>
              <dt className="text-muted">{R.detail.mitre}</dt>
              <dd className={`${MONO} break-words`}>{orDash(alert.mitre_ids.join(", "))}</dd>
              <dt className="text-muted">{R.detail.count}</dt>
              <dd>{alert.occurrence_count}</dd>
            </dl>
            <div className="space-y-1.5">
              <h3 className="text-[13px] font-semibold text-[#aeb9c6]">{R.detail.rawLog}</h3>
              <LogBlock text={alert.raw_log} />
              {alert.raw_log_truncated_for_display && (
                <p className="text-xs text-muted">{R.detail.rawLogCut}</p>
              )}
            </div>
          </div>
        )}
      </details>

      <div role="group" aria-label={R.actionsLabel} className="flex flex-wrap items-center gap-2">
        {(["true_positive", "false_positive"] as const).map((label) => (
          <button
            key={label}
            type="button"
            aria-pressed={alert.label === label}
            onClick={() => choose(label)}
            className={`${BUTTON} ${alert.label === label ? PRESSED[label] : IDLE}`}
          >
            {R.action[label]}
          </button>
        ))}
        <button
          type="button"
          aria-disabled={alert.label === null}
          onClick={clear}
          className={`${BUTTON} ${IDLE}`}
        >
          {R.action.clear}
        </button>
      </div>

      {error !== null && (
        <p
          role="alert"
          className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3.5 py-2.5 text-[13px] leading-snug text-[#fda4af]"
        >
          {error}
        </p>
      )}
    </li>
  );
}
