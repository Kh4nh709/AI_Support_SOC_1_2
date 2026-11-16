// The dialog of undo and false positive (spec section 7): the ticket, what happens when it is done, an optional note
// counted to 500, and, when the server says `strong_warning`, a stronger warning (an isolated machine, the domain
// controller) and a deliberate confirm (a box to tick before the button works). It is the repo's own ConfirmDialog
// (focus, Tab held inside, Escape, labelled); its state is here, not in the row, so the list asking again neither closes it
// nor wipes the note being typed. Keep sends at once and has no dialog.
import { useId, useState } from "react";
import type { SoarDecision, SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { ConfirmDialog } from "../admin/ConfirmDialog";
import { NOTE_MAX, actionTextOf, strongWarningOf } from "./model";

export type DialogDecision = Extract<SoarDecision, "undo" | "fp">;

const FIELD =
  "w-full rounded border border-border bg-ground px-2 py-1 text-sm text-text focus-visible:outline-2 focus-visible:outline-text";

export function DecisionDialog({
  row,
  decision,
  onConfirm,
  onCancel,
}: {
  /** The ticket as it was when the person pressed the button: the list may have lost it since. */
  row: SoarReview;
  decision: DialogDecision;
  onConfirm: (note: string) => void;
  onCancel: () => void;
}) {
  const [note, setNote] = useState("");
  const [understood, setUnderstood] = useState(false);
  const noteId = useId();
  const strong = row.strong_warning === true;
  const title = S.soar.dialog.title[strong ? (`${decision}Strong` as const) : decision];
  return (
    <ConfirmDialog
      title={title}
      confirmLabel={S.soar.dialog.confirm[decision]}
      tone={strong ? "danger" : "primary"}
      confirmDisabled={strong && !understood}
      onConfirm={() => onConfirm(note.trim())}
      onCancel={onCancel}
    >
      <p className="wrap-anywhere">{S.soar.dialog.subject(row.id, actionTextOf(row))}</p>
      {strong && (
        <p className="rounded border border-critical bg-critical-bg px-3 py-2 font-medium text-text wrap-anywhere">
          {strongWarningOf(row, decision)}
        </p>
      )}
      <p>{S.soar.dialog.after[decision]}</p>
      {strong && (
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
    </ConfirmDialog>
  );
}
