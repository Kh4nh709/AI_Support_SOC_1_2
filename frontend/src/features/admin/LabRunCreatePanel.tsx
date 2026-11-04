// The "Tạo lần chạy" panel of the lab runs page (P14-T10): a name, a purpose and the window the run covers.
//
// The two times are entered in the console's zone, +07:00 (labModel.ts), and posted as ISO 8601 with that offset. What
// the panel checks before it posts is what cannot be sent at all (`checkNewRun`); the order of the two times and the
// years are the server's to judge. Its answers show beside the input they name, in words: a `422 {field, reason}` at
// the field (`labFieldText`), and the `409 overlap` under the two times, which both belong to. Anything else (a refused
// role, a 5xx, a lost connection) is one line in the form, in the console's generic text; a code is never shown.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState, type FormEvent } from "react";
import {
  LAB_LIMITS,
  LAB_PURPOSES,
  createLabRun,
  labErrorOf,
  type LabPurpose,
} from "../../api/admin";
import { S } from "../../strings";
import { invalidateAfter } from "./adminKeys";
import {
  NEW_RUN_FIELDS,
  checkNewRun,
  isNewRunField,
  labFieldText,
  newRunBody,
  type NewRunField,
  type NewRunValues,
} from "./labModel";
import { useSubmitLatch } from "./useSubmitLatch";

const C = S.admin.lab.runsPage.create;

const EMPTY: NewRunValues = { name: "", purpose: null, starts: "", ends: "" };

/** The text beside each input that is wrong. */
type Messages = Partial<Record<NewRunField, string>>;

const LABEL = "flex flex-col gap-1.5 text-[13px] text-[#aeb9c6]";
const INPUT =
  "h-10 w-full rounded-md border border-[#2e3a48] bg-[#0f141b] px-3 text-sm text-text focus-visible:outline-2 focus-visible:outline-text aria-invalid:border-[#5a2e36]";
const ERROR = "text-[12.5px] text-[#fda4af]";

export function LabRunCreatePanel({
  onCreated,
}: {
  /** The run was made (and the list is being read again): say so. */
  onCreated: (notice: string) => void;
}) {
  const client = useQueryClient();
  const [values, setValues] = useState<NewRunValues>(EMPTY);
  const [messages, setMessages] = useState<Messages>({});
  const [windowError, setWindowError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const titleId = useId();
  const ids = {
    name: useId(),
    purpose: useId(),
    starts_at: useId(),
    ends_at: useId(),
  } satisfies Record<NewRunField, string>;
  const hintId = useId();
  const windowErrorId = useId();
  const fields = useRef<Partial<Record<NewRunField, HTMLElement | null>>>({});

  const mutation = useMutation({
    mutationFn: createLabRun,
    onMutate: () => {
      setWindowError(null);
      setFormError(null);
    },
    onSuccess: async (made) => {
      await invalidateAfter(client, "createLabRun");
      setValues(EMPTY);
      setMessages({});
      onCreated(C.done(made.name));
    },
    onError: (error) => {
      const refusal = labErrorOf(error);
      if (refusal.kind === "overlap") setWindowError(C.overlap);
      else if (refusal.kind === "field" && isNewRunField(refusal.field)) {
        setMessages({ [refusal.field]: labFieldText(refusal.field, refusal.reason) });
      } else setFormError(S.common.unknownError);
    },
  });
  // One press of the button sends one write, even for two presses in one tick (see useSubmitLatch.ts).
  const run = useSubmitLatch(mutation);

  /** Sets what was typed, and drops the message of the input it was typed in (a time also drops the overlap). */
  const edit = (patch: Partial<NewRunValues>, field: NewRunField) => {
    setValues((current) => ({ ...current, ...patch }));
    setMessages((current) => {
      const next = { ...current };
      delete next[field];
      return next;
    });
    if (field === "starts_at" || field === "ends_at") setWindowError(null);
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setWindowError(null);
    setFormError(null);
    const found = checkNewRun(values);
    const wrong: Messages = {};
    for (const field of NEW_RUN_FIELDS) {
      const reason = found[field];
      if (reason !== undefined) wrong[field] = labFieldText(field, reason);
    }
    setMessages(wrong);
    const first = NEW_RUN_FIELDS.find((field) => wrong[field] !== undefined);
    if (first !== undefined) {
      fields.current[first]?.focus();
      return;
    }
    const body = newRunBody(values);
    if (body !== null) run(body);
  };

  const invalid = (field: NewRunField) => (messages[field] !== undefined ? true : undefined);
  const errorId = (field: NewRunField) => `${ids[field]}-error`;
  const describedBy = (field: NewRunField, ...more: (string | undefined)[]) =>
    [...more, messages[field] !== undefined ? errorId(field) : undefined]
      .filter((id) => id !== undefined)
      .join(" ") || undefined;
  const message = (field: NewRunField) =>
    messages[field] !== undefined && (
      <p id={errorId(field)} role="alert" className={ERROR}>
        {messages[field]}
      </p>
    );
  const windowDescribedBy = windowError === null ? undefined : windowErrorId;

  return (
    <section
      aria-labelledby={titleId}
      className="w-full max-w-[380px] rounded-[10px] border border-[#3a4757] bg-surface px-[22px] py-5"
    >
      <form noValidate onSubmit={submit} className="flex flex-col gap-3.5">
        <h2 id={titleId} className="text-[17px] font-semibold">
          {C.title}
        </h2>

        <div className={LABEL}>
          <label htmlFor={ids.name}>{C.name}</label>
          <input
            id={ids.name}
            ref={(el) => {
              fields.current.name = el;
            }}
            type="text"
            autoComplete="off"
            placeholder={C.namePlaceholder}
            value={values.name}
            aria-invalid={invalid("name")}
            aria-describedby={describedBy("name")}
            onChange={(event) => edit({ name: event.target.value }, "name")}
            className={INPUT}
          />
          <p className="text-xs text-muted">{C.nameHint(LAB_LIMITS.nameMax)}</p>
          {message("name")}
        </div>

        <fieldset
          role="radiogroup"
          aria-invalid={invalid("purpose")}
          aria-describedby={describedBy("purpose")}
          className="m-0 flex flex-col gap-2 border-0 p-0"
        >
          <legend className="mb-1.5 text-[13px] text-[#aeb9c6]">{C.purpose}</legend>
          {LAB_PURPOSES.map((purpose: LabPurpose, index) => (
            <label
              key={purpose}
              className="flex items-start gap-2.5 rounded-lg border border-[#2e3a48] px-3 py-2.5 text-[13.5px]"
            >
              <input
                type="radio"
                name={ids.purpose}
                value={purpose}
                checked={values.purpose === purpose}
                ref={(el) => {
                  if (index === 0) fields.current.purpose = el;
                }}
                onChange={() => edit({ purpose }, "purpose")}
                className="mt-1"
              />
              <span>
                <b className="font-semibold">{S.admin.lab.purpose[purpose]}</b>
                <span className="block text-[12.5px] text-muted">{C.purposeHelp[purpose]}</span>
              </span>
            </label>
          ))}
          {message("purpose")}
        </fieldset>

        <div className={LABEL}>
          <label htmlFor={ids.starts_at}>{C.starts}</label>
          <input
            id={ids.starts_at}
            ref={(el) => {
              fields.current.starts_at = el;
            }}
            type="datetime-local"
            step={1}
            value={values.starts}
            aria-invalid={invalid("starts_at")}
            aria-describedby={describedBy("starts_at", hintId, windowDescribedBy)}
            onChange={(event) => edit({ starts: event.target.value }, "starts_at")}
            className={INPUT}
          />
          {message("starts_at")}
        </div>

        <div className={LABEL}>
          <label htmlFor={ids.ends_at}>{C.ends}</label>
          <input
            id={ids.ends_at}
            ref={(el) => {
              fields.current.ends_at = el;
            }}
            type="datetime-local"
            step={1}
            value={values.ends}
            aria-invalid={invalid("ends_at")}
            aria-describedby={describedBy("ends_at", hintId, windowDescribedBy)}
            onChange={(event) => edit({ ends: event.target.value }, "ends_at")}
            className={INPUT}
          />
          {message("ends_at")}
        </div>

        <p id={hintId} className="text-xs leading-normal text-muted">
          {C.timeHint}
        </p>

        {windowError !== null && (
          <p
            id={windowErrorId}
            role="alert"
            className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3.5 py-3 text-[13.5px] leading-snug text-[#fda4af]"
          >
            {windowError}
          </p>
        )}
        {formError !== null && (
          <p
            role="alert"
            className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3.5 py-3 text-[13.5px] leading-snug text-[#fda4af]"
          >
            {formError}
          </p>
        )}

        <button
          type="submit"
          disabled={mutation.isPending}
          aria-busy={mutation.isPending || undefined}
          className="h-11 rounded-lg bg-blue-600 text-[15px] font-semibold text-white hover:bg-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:opacity-60"
        >
          {mutation.isPending ? S.admin.common.working : C.submit}
        </button>
      </form>
    </section>
  );
}
