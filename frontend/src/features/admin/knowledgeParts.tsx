// The small pieces the three views of the knowledge page share (P13-T06): the class strings of the console, the
// words for a conclusion, the reason dialog of a rejection and of a retirement, and a value shown as text.
// Everything a person or a model wrote goes through React's text nodes: nothing here sets markup.
import { useId, type ReactNode } from "react";
import { KNOWLEDGE_LIMITS } from "../../api/admin";
import { S, labelOf } from "../../strings";
import { asText } from "../tier2/parts";
import { ConfirmDialog } from "./ConfirmDialog";

export const PANEL = "rounded-[10px] border border-border bg-surface";

export const BUTTON_PRIMARY =
  "h-10 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-50";
export const BUTTON_OUTLINE =
  "h-10 rounded-lg border border-border px-3.5 text-sm text-text hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-50";
export const BUTTON_DANGER =
  "h-10 rounded-lg border border-[#5a2e36] px-3.5 text-sm text-[#fda4af] hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-50";
export const FIELD_CLASS =
  "w-full rounded-md border border-border bg-ground px-2.5 py-1.5 text-sm focus-visible:outline-2 focus-visible:outline-text read-only:opacity-80 aria-[invalid=true]:border-critical";
export const ERROR_CLASS = "text-[13px] leading-snug text-[#fda4af]";

/** An alert's status and a case's conclusion share one table: a draft's `conclusion` is either. */
const CONCLUSION_LABELS = { ...S.status, ...S.caseStatus };

export const conclusionLabel = (code: string | null | undefined): string =>
  labelOf(CONCLUSION_LABELS, code);

/** A mark beside a title: `warn` is the canvas's amber (a conflict, a warning), `neutral` the quiet one. */
export function Mark({
  tone = "neutral",
  children,
}: {
  tone?: "neutral" | "warn";
  children: ReactNode;
}) {
  const colours =
    tone === "warn" ? "bg-[#2a1a0a] text-[#fcd9a8]" : "border border-border text-[#aeb9c6]";
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold whitespace-nowrap ${colours}`}
    >
      {children}
    </span>
  );
}

/** The waiting line of a view that has not heard from the server yet. */
export function Waiting() {
  return (
    <p role="status" className="text-sm text-muted">
      {S.common.loading}
    </p>
  );
}

/** A failed read, in place of the list or the view, with the way to ask again when asking again can help. */
export function ReadError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-[#3a4757] p-6 text-center text-[13.5px] text-[#c9d3df]"
    >
      <span>{message}</span>
      {onRetry !== undefined && (
        <button type="button" onClick={onRetry} className={BUTTON_OUTLINE}>
          {S.common.retry}
        </button>
      )}
    </div>
  );
}

/** A value as text in a box that scrolls: JSON for an object, the text itself for a string. Never markup. */
export function TextBox({ value, label }: { value: unknown; label?: string }) {
  const text =
    typeof value === "string"
      ? value
      : (() => {
          try {
            return JSON.stringify(value, null, 2) ?? asText(value);
          } catch {
            return asText(value);
          }
        })();
  return (
    <pre
      tabIndex={0}
      role={label === undefined ? undefined : "region"}
      aria-label={label}
      className="max-h-80 overflow-auto rounded border border-border bg-ground p-2.5 font-mono text-xs break-words whitespace-pre-wrap focus-visible:outline-2 focus-visible:outline-text"
    >
      {text}
    </pre>
  );
}

/**
 * The dialog of a rejection and of a retirement: a reason of 1 to 500 characters is required, and the confirm
 * button waits for one. A refusal of the server about the reason (`422 reason`) is shown at the input.
 */
export function ReasonDialog(props: {
  title: string;
  body: string;
  confirmLabel: string;
  reasonLabel: string;
  reason: string;
  onReason: (reason: string) => void;
  /** The 422 about the reason, worded; null when there is none. */
  reasonError: string | null;
  /** Any other failure of the write, worded. */
  error: string | null;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const inputId = useId();
  const countId = useId();
  const errorId = useId();
  // Code points, as the backend counts (Python `len`): an emoji is one, though JavaScript `length` says two.
  const used = [...props.reason.trim()].length;
  const tooLong = used > KNOWLEDGE_LIMITS.reasonMax;
  const describedBy = [countId, props.reasonError === null ? null : errorId]
    .filter((id) => id !== null)
    .join(" ");
  return (
    <ConfirmDialog
      title={props.title}
      confirmLabel={props.confirmLabel}
      tone="danger"
      busy={props.busy}
      error={props.error ?? undefined}
      confirmDisabled={used === 0 || tooLong}
      onConfirm={props.onConfirm}
      onCancel={props.onCancel}
    >
      <p>{props.body}</p>
      <label htmlFor={inputId} className="block text-sm font-medium">
        {props.reasonLabel}
      </label>
      <textarea
        id={inputId}
        autoFocus
        rows={3}
        value={props.reason}
        onChange={(event) => props.onReason(event.target.value)}
        aria-invalid={props.reasonError !== null || tooLong ? true : undefined}
        aria-describedby={describedBy}
        className={FIELD_CLASS}
      />
      <p id={countId} className="text-xs text-muted">
        {S.admin.knowledgePage.draft.action.reasonCount(used, KNOWLEDGE_LIMITS.reasonMax)}
      </p>
      {props.reasonError !== null && (
        <p id={errorId} className={ERROR_CLASS}>
          {props.reasonError}
        </p>
      )}
    </ConfirmDialog>
  );
}
