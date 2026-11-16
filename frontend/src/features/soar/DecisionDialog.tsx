// The dialog of undo and false positive (spec section 7): the ticket, what happens when it is done, an optional note
// counted to 500, and, when the server says `strong_warning`, a stronger warning worded by the action and a deliberate
// confirm (a box to tick before the button works). It is the repo's own ConfirmDialog (focus, Tab held inside, Escape,
// labelled); its state is here, not in the row, so the list asking again neither closes it nor wipes the note being typed.
//
// It follows the LIVE row (`live`, the ticket as the list now has it; `row` is only what it was when the dialog opened):
//   - the ticket changed (its status, `updated_at` or `allowed_decisions`): "Phiếu vừa thay đổi: <trạng thái> (<ai>)" and the
//     confirm waits for a box that says the person has seen it; a second change asks again;
//   - the decision is no longer allowed: the dialog says why and has no confirm, only "Đóng";
//   - the ticket has left the list (`gone`): it says so and has no confirm either. This is the simpler of the two ways: the page
//     has no second source for the row (a detail read could confirm it, at the price of a second request to wait for), so
//     the person closes the dialog and looks at the ticket again.
// Keep sends at once and has no dialog.
import { useId, useState } from "react";
import type { SoarDecision, SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { ConfirmDialog } from "../admin/ConfirmDialog";
import { NOTE_MAX, actionTextOf, statusText, strongTitleOf, strongWarningOf } from "./model";

export type DialogDecision = Extract<SoarDecision, "undo" | "fp">;

const FIELD =
  "w-full rounded border border-border bg-ground px-2 py-1 text-sm text-text focus-visible:outline-2 focus-visible:outline-text";

/** What the dialog compares: the status, the time of the last write, and which decisions the caller may take. */
const stateKey = (row: SoarReview): string =>
  [
    row.status,
    row.updated_at,
    Array.isArray(row.allowed_decisions) ? [...row.allowed_decisions].sort().join(",") : "",
  ].join("|");

const said = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

export function DecisionDialog({
  row,
  live,
  gone,
  decision,
  onConfirm,
  onCancel,
}: {
  /** The ticket as it was when the person pressed the button: the list may have lost it or changed it since. */
  row: SoarReview;
  /** The ticket as the list has it now; null when the list has no row of that id. */
  live: SoarReview | null;
  /** The list is loaded and the ticket is not in it any more. */
  gone: boolean;
  decision: DialogDecision;
  /** Told the note, and the ticket as it now is. */
  onConfirm: (note: string, current: SoarReview) => void;
  onCancel: () => void;
}) {
  const [note, setNote] = useState("");
  const [understood, setUnderstood] = useState(false);
  // The state of the ticket the person has said they have seen (it asks again when the ticket changes again).
  const [seen, setSeen] = useState<string | null>(null);
  const noteId = useId();
  const hintId = useId();
  const current = live ?? row;
  const strong = current.strong_warning === true;
  const allowed =
    Array.isArray(current.allowed_decisions) && current.allowed_decisions.includes(decision);
  const changed = live !== null && stateKey(live) !== stateKey(row);
  const acknowledged = changed && seen === stateKey(live);
  const title = strongTitleOf(current, decision);
  const available = !gone && allowed;
  // The boxes still to tick before the confirm opens: the risk first, then the change. While one is, the confirm is shut.
  const waiting = !available
    ? null
    : strong && !understood
      ? S.soar.dialog.understand
      : changed && !acknowledged
        ? S.soar.dialog.acknowledgeChange
        : null;

  let problem: string | null = null;
  if (gone) problem = S.soar.dialog.gone;
  else if (!allowed) problem = S.soar.dialog.notAllowed(statusText(current));
  else if (changed) {
    problem = S.soar.dialog.changed(
      statusText(current),
      said(current.decided_by) ?? said(current.locked_by),
    );
  }

  return (
    <ConfirmDialog
      title={title}
      confirmLabel={S.soar.dialog.confirm[decision]}
      cancelLabel={available ? undefined : S.common.close}
      // The shared dialog shows its own confirm only when it can be pressed: a shut one is drawn below, in the normal disabled
      // look (its own is the red button at 60 % opacity, which looks pressable).
      hideConfirm={!available || waiting !== null}
      tone={strong ? "danger" : "primary"}
      error={problem}
      onConfirm={() => onConfirm(note.trim(), current)}
      onCancel={onCancel}
    >
      <p className="wrap-anywhere">{S.soar.dialog.subject(current.id, actionTextOf(current))}</p>
      {strong && (
        <p className="rounded border border-critical bg-critical-bg px-3 py-2 font-medium text-text wrap-anywhere">
          {strongWarningOf(current, decision)}
        </p>
      )}
      <p>{S.soar.dialog.after[decision]}</p>
      {strong && available && (
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={understood}
            onChange={(event) => setUnderstood(event.target.checked)}
            className="mt-0.5"
          />
          <span>{S.soar.dialog.understand}</span>
        </label>
      )}
      {changed && available && live !== null && (
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setSeen(event.target.checked ? stateKey(live) : null)}
            className="mt-0.5"
          />
          <span>{S.soar.dialog.acknowledgeChange}</span>
        </label>
      )}
      <div className="flex flex-col gap-1">
        <label htmlFor={noteId}>{S.soar.dialog.note}</label>
        <textarea
          id={noteId}
          autoFocus
          rows={3}
          maxLength={NOTE_MAX}
          value={note}
          onChange={(event) => setNote(event.target.value)}
          className={FIELD}
        />
        <p className="text-right text-xs">{S.soar.dialog.noteCount(note.length, NOTE_MAX)}</p>
      </div>
      {waiting !== null && (
        <div className="flex items-center justify-between gap-3">
          <p id={hintId} className="text-xs text-muted">
            {S.soar.dialog.shutHint(waiting)}
          </p>
          <button
            type="button"
            disabled
            aria-describedby={hintId}
            className="h-10 shrink-0 rounded-lg border border-border px-3.5 text-sm text-muted disabled:opacity-50"
          >
            {S.soar.dialog.confirm[decision]}
          </button>
        </div>
      )}
    </ConfirmDialog>
  );
}
