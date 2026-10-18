// The form beside the cluster (spec §4.6): the label, how sure the labeller is, a one-line note of at most 200
// characters with its counter, "Lưu nhãn và sang cụm tiếp" and "Hoàn tác nhãn vừa gán".
//
// It checks what the server would refuse before it posts, and says so at the field: no label chosen, a note over
// the limit. It posts nothing itself: `onSave` takes the values, and the page owns the write, its latch and
// what the server answers. One form per cluster (the page keys it by the cluster), so a new cluster starts empty.
import { useId, useRef, useState, type FormEvent } from "react";
import {
  ADMIN_LIMITS,
  LABEL_CHOICES,
  LABEL_CONFIDENCES,
  type LabelChoice,
  type LabelConfidence,
} from "../../api/admin";
import { S, adminReasonText } from "../../strings";

const F = S.admin.labelsPage.form;

/** What the labeller chose. `note` is trimmed on one line; empty when there is none. */
export type LabelValues = { label: LabelChoice; confidence: LabelConfidence; note: string };

/** `confidence` starts at 2, "vừa": the old page's own default. */
const DEFAULT_CONFIDENCE: LabelConfidence = 2;

/** The note as the server will read it: its lines joined by a space, trimmed (`clean_note` of tier1/labels.py). */
function oneLine(note: string): string {
  return note
    .split(/\r\n|\r|\n/)
    .join(" ")
    .trim();
}

/** Characters as the server counts them (Python's `len`): a code point, not a UTF-16 unit. */
function lengthOf(text: string): number {
  return [...text].length;
}

// Whole class names: Tailwind finds a class by reading the source.
const CHOICE =
  "flex cursor-pointer items-start gap-2.5 rounded-lg border border-[#2e3a48] px-3 py-2.5 text-[13.5px] has-checked:border-[#5b8def] has-checked:bg-[#13203a] has-focus-visible:outline-2 has-focus-visible:outline-text";
const CONFIDENCE =
  "flex h-10 cursor-pointer items-center justify-center gap-1.5 rounded-md border border-[#2e3a48] text-[13px] has-checked:border-[#5b8def] has-checked:bg-[#13203a] has-focus-visible:outline-2 has-focus-visible:outline-text";
const BUTTON_OFF = "disabled:cursor-not-allowed disabled:opacity-60";
const INVALID = "text-xs text-[#fda4af]";

export function LabelForm({
  working,
  canUndo,
  error,
  onSave,
  onUndo,
}: {
  /** A write is in flight: which one. Both buttons are disabled meanwhile. */
  working: "save" | "undo" | null;
  /** The labeller has something to take back, and the set is not frozen. */
  canUndo: boolean;
  /** What the server said to the last save or undo, in words, or null. */
  error: string | null;
  onSave: (values: LabelValues) => void;
  onUndo: () => void;
}) {
  const [label, setLabel] = useState<LabelChoice | null>(null);
  const [confidence, setConfidence] = useState<LabelConfidence>(DEFAULT_CONFIDENCE);
  const [note, setNote] = useState("");
  const [labelMissing, setLabelMissing] = useState(false);
  const [noteError, setNoteError] = useState<string | null>(null);
  const firstChoice = useRef<HTMLInputElement>(null);
  const noteInput = useRef<HTMLInputElement>(null);
  const titleId = useId();
  const labelErrorId = useId();
  const noteErrorId = useId();
  const countId = useId();
  const busy = working !== null;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (label === null) {
      setLabelMissing(true);
      firstChoice.current?.focus();
      return;
    }
    const text = oneLine(note);
    if (lengthOf(text) > ADMIN_LIMITS.noteMax) {
      setNoteError(adminReasonText({ reason: "too_long", max: ADMIN_LIMITS.noteMax }));
      noteInput.current?.focus();
      return;
    }
    onSave({ label, confidence, note: text });
  }

  return (
    <section
      aria-labelledby={titleId}
      className="sticky top-4 flex w-[340px] shrink-0 flex-col gap-3.5 rounded-[10px] border border-[#3a4757] bg-surface px-[22px] py-5"
    >
      <h2 id={titleId} className="text-[17px] font-semibold">
        {F.title}
      </h2>
      <form noValidate onSubmit={submit} className="flex flex-col gap-3.5">
        <fieldset
          aria-describedby={labelMissing ? labelErrorId : undefined}
          className="m-0 flex flex-col gap-2 border-none p-0"
        >
          <legend className="mb-1.5 text-[13px] text-[#aeb9c6]">{F.label}</legend>
          {LABEL_CHOICES.map((choice, index) => (
            <label key={choice} className={CHOICE}>
              <input
                ref={index === 0 ? firstChoice : undefined}
                type="radio"
                name="label"
                value={choice}
                checked={label === choice}
                onChange={() => {
                  setLabel(choice);
                  setLabelMissing(false);
                }}
                className="mt-0.5"
              />
              <span>
                <b className="font-semibold">{F.choices[choice]}</b>
                <br />
                <span className="text-[12.5px] text-muted">{choice}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {labelMissing && (
          <p id={labelErrorId} role="alert" className={INVALID}>
            {F.noLabel}
          </p>
        )}

        <fieldset className="m-0 flex flex-col gap-1.5 border-none p-0">
          <legend className="mb-1.5 text-[13px] text-[#aeb9c6]">{F.confidence}</legend>
          <div className="grid grid-cols-3 gap-1.5">
            {LABEL_CONFIDENCES.map((level) => (
              <label key={level} className={CONFIDENCE}>
                <input
                  type="radio"
                  name="confidence"
                  value={level}
                  checked={confidence === level}
                  onChange={() => setConfidence(level)}
                />
                {F.confidences[level]}
              </label>
            ))}
          </div>
        </fieldset>

        <div className="flex flex-col gap-1.5">
          <label htmlFor={`${titleId}-note`} className="text-[13px] text-[#aeb9c6]">
            {F.note}
          </label>
          <input
            id={`${titleId}-note`}
            ref={noteInput}
            type="text"
            // No `maxLength`: it counts UTF-16 units and the server counts code points (an emoji is two units),
            // so it would stop a note the server takes. The counter and the error at the field are the limit.
            value={note}
            aria-invalid={noteError !== null}
            aria-describedby={noteError === null ? countId : `${countId} ${noteErrorId}`}
            onChange={(event) => {
              setNote(event.target.value);
              setNoteError(null);
            }}
            className="box-border h-10 rounded-md border border-[#2e3a48] bg-[#0f141b] px-3 text-sm text-text focus-visible:outline-2 focus-visible:outline-text aria-invalid:border-[#f87171]"
          />
          <span id={countId} className="self-end text-xs text-muted">
            {F.noteCount(lengthOf(note), ADMIN_LIMITS.noteMax)}
          </span>
          {noteError !== null && (
            <p id={noteErrorId} role="alert" className={INVALID}>
              {noteError}
            </p>
          )}
        </div>

        {error !== null && (
          <div
            role="alert"
            className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3 py-2.5 text-[13px] leading-snug text-[#fda4af]"
          >
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={busy}
          aria-busy={working === "save"}
          className={`h-11 rounded-lg bg-[#2563eb] text-[15px] font-semibold text-white hover:bg-[#1d4fd7] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text ${BUTTON_OFF}`}
        >
          {working === "save" ? S.admin.common.saving : F.save}
        </button>
        {canUndo && (
          <button
            type="button"
            disabled={busy}
            aria-busy={working === "undo"}
            onClick={onUndo}
            className={`h-10 rounded-lg border border-[#2e3a48] text-sm text-[#c9d3df] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text ${BUTTON_OFF}`}
          >
            {working === "undo" ? F.undoing : F.undo}
          </button>
        )}
        <p className="text-xs leading-normal text-muted">{F.hint}</p>
      </form>
    </section>
  );
}
