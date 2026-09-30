// The forms of the decision panel: decide, escalate, reopen. They hold what the analyst is typing and hand
// a finished action to the panel, which owns the request; while one is in flight (`busy`) they are shut.
import { useId, useState, type FormEvent, type ReactNode } from "react";
import { CASE_SEVERITIES, type AlertView, type CaseSeverity, type Decision } from "../../api/tier1";
import { S, labelOf } from "../../strings";
import { readDraft, writeDraft } from "./draft";

export type Action =
  | { kind: "acknowledge" }
  | { kind: "decide"; decision: Decision; reason: string; seen: number }
  | { kind: "escalate"; title: string; severity: CaseSeverity }
  | { kind: "reopen"; reason: string };

// Whole class names, written out: Tailwind finds a class by reading the source.
const FIELD =
  "w-full rounded border border-border bg-ground px-2 py-1 text-sm aria-invalid:border-critical focus-visible:outline-2 focus-visible:outline-text";
export const BUTTON =
  "rounded border border-ai-border bg-ai-surface px-3 py-1 text-sm hover:bg-ground disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-text";

/** A labelled field, its hint, and the server's message about it, tied to it for a screen reader. */
function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error: string | null;
  children: (props: {
    id: string;
    describedBy: string | undefined;
    invalid: true | undefined;
  }) => ReactNode;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const ids = [hint ? hintId : null, error ? errorId : null].filter((x) => x !== null);
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-sm">
        {label}
      </label>
      {children({
        id,
        describedBy: ids.length > 0 ? ids.join(" ") : undefined,
        invalid: error ? true : undefined,
      })}
      {hint && (
        <p id={hintId} className="text-xs text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} role="alert" className="text-xs text-critical">
          {error}
        </p>
      )}
    </div>
  );
}

function ReasonBox({
  label,
  value,
  onChange,
  error,
  disabled,
}: {
  label: string;
  value: string;
  onChange: (text: string) => void;
  error: string | null;
  disabled: boolean;
}) {
  return (
    <Field label={label} hint={S.decision.reasonHint} error={error}>
      {({ id, describedBy, invalid }) => (
        <textarea
          id={id}
          rows={3}
          maxLength={500}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
          aria-invalid={invalid}
          aria-describedby={describedBy}
          className={FIELD}
        />
      )}
    </Field>
  );
}

type FormProps = {
  busy: boolean;
  /** The server's message about the field of this form (a 422), or null. */
  error: string | null;
  onRun: (action: Action) => void;
};

const DECISIONS: readonly [Decision, string][] = [
  ["false_positive", S.decision.falsePositive],
  ["benign", S.decision.benign],
];

/** Close the cluster as a false positive or as benign, with a reason. It sends the count the analyst was shown. */
export function DecideForm({
  view,
  userId,
  busy,
  error,
  onRun,
}: FormProps & { view: AlertView; userId: string }) {
  const [choice, setChoice] = useState<Decision | null>(null);
  // Restored once, when the form is first drawn: a draft this user left before the session ended.
  const [reason, setReason] = useState(() => readDraft(view.alert_id, userId));
  // The count on screen is the count sent: a cluster that has grown since is the server's 409 to report.
  const seen = view.occurrence_count;
  const ready = choice !== null && reason.trim() !== "" && typeof seen === "number" && !busy;

  function change(text: string) {
    setReason(text);
    writeDraft(view.alert_id, userId, text);
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready || choice === null || typeof seen !== "number") return;
    onRun({ kind: "decide", decision: choice, reason: reason.trim(), seen });
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <fieldset className="space-y-1" disabled={busy}>
        <legend className="text-sm">{S.decision.choose}</legend>
        {DECISIONS.map(([code, label]) => (
          <label key={code} className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name="decision"
              value={code}
              checked={choice === code}
              onChange={() => setChoice(code)}
            />
            {label}
          </label>
        ))}
      </fieldset>
      <ReasonBox
        label={S.decision.reason}
        value={reason}
        onChange={change}
        error={error}
        disabled={busy}
      />
      {typeof seen === "number" && (
        <p className="text-xs text-muted">{S.decision.seenHint(seen)}</p>
      )}
      <button type="submit" disabled={!ready} className={BUTTON}>
        {S.decision.submit}
      </button>
    </form>
  );
}

const asSeverity = (x: string | null | undefined): CaseSeverity =>
  CASE_SEVERITIES.find((s) => s === x) ?? "medium";

/** The title a case gets unless the analyst writes another: what the alert is, and where. */
function defaultTitle(view: AlertView): string {
  const named = [view.category, view.agent_name].filter((x) => typeof x === "string" && x !== "");
  return named.length > 0 ? named.join(" — ") : (view.description ?? view.alert_id);
}

/** Send the cluster to Tier 2 as a case. */
export function EscalateForm({ view, busy, error, onRun }: FormProps & { view: AlertView }) {
  const [title, setTitle] = useState(() => defaultTitle(view));
  const [severity, setSeverity] = useState<CaseSeverity>(() => asSeverity(view.severity));
  const ready = title.trim() !== "" && !busy;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (ready) onRun({ kind: "escalate", title: title.trim(), severity });
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <fieldset className="space-y-3 border-t border-border pt-3" disabled={busy}>
        <legend className="text-sm">{S.decision.escalate}</legend>
        <Field label={S.decision.caseTitle} error={error}>
          {({ id, describedBy, invalid }) => (
            <input
              id={id}
              type="text"
              maxLength={200}
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              aria-invalid={invalid}
              aria-describedby={describedBy}
              className={FIELD}
            />
          )}
        </Field>
        <Field label={S.decision.severity} error={null}>
          {({ id }) => (
            <select
              id={id}
              value={severity}
              onChange={(e) => setSeverity(asSeverity(e.target.value))}
              className={FIELD}
            >
              {CASE_SEVERITIES.map((code) => (
                <option key={code} value={code}>
                  {labelOf(S.band, code)}
                </option>
              ))}
            </select>
          )}
        </Field>
      </fieldset>
      <button type="submit" disabled={!ready} className={BUTTON}>
        {S.decision.escalate}
      </button>
    </form>
  );
}

/** Open an alert the system closed by itself again, with a reason. */
export function ReopenForm({ busy, error, onRun }: FormProps) {
  const [reason, setReason] = useState("");
  const ready = reason.trim() !== "" && !busy;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (ready) onRun({ kind: "reopen", reason: reason.trim() });
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <ReasonBox
        label={S.decision.reopenReason}
        value={reason}
        onChange={setReason}
        error={error}
        disabled={busy}
      />
      <button type="submit" disabled={!ready} className={BUTTON}>
        {S.decision.reopen}
      </button>
    </form>
  );
}
