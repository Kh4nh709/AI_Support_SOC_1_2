// The "Hạn mức" block of the LLM page (spec §4.3, §5.2): the three limits the admin may change on the web,
// or, when the stored limits cannot be read, the read-only panel that says the model is stopped.
//
// The form follows the route and does not copy it:
//   - each field's `min` and `max` are `limits.bounds[field]` from the answer (DEC-202: the timeout's max is
//     derived from the job lock on the server), and the source line of each field is
//     `limits.sources[LIMIT_KEY_OF_FIELD[field]]`: `.env`, or who saved it on the web and when;
//   - a blank, a decimal or a value outside the bounds is shown at the field before anything is sent, in the
//     route's own words; the route's 422 `{field, reason}` is shown at the field too (and the dialog closes,
//     because the admin has to correct a field, not confirm again);
//   - "Lưu hạn mức" opens the confirmation, which lists the changed fields only (old → new) and warns when
//     the new cap is not above what the month has spent, because the adapter stops at `spent >= cap`;
//   - the PUT answers `{limits}`: the page shows that at once (in every cached range) and then reads again
//     through `invalidateAfter("putLlmLimits")`.
// A failure that no field explains (a 503, a 403, the network) is shown inside the dialog, which stays open.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import {
  LIMIT_FIELDS,
  LIMIT_KEY_OF_FIELD,
  adminErrorOf,
  putLlmLimits,
  type AdminError,
  type LimitField,
  type LimitSource,
  type LimitsChange,
  type LimitsOut,
  type LlmUsage,
} from "../../api/admin";
import { DataTable, type Column } from "../../components/DataTable";
import { formatDateTime } from "../../format";
import { S, adminReasonText } from "../../strings";
import { ConfirmDialog } from "./ConfirmDialog";
import { adminKeys, invalidateAfter } from "./adminKeys";
import { formatCount, formatUsd, limitChanges, type LimitFault } from "./llmFigures";

const L = S.admin.llmPage;

const PANEL = "flex flex-col gap-3 rounded-[10px] border bg-surface px-5 py-[18px]";
const INPUT =
  "h-10 w-full rounded-md border bg-[#0f141b] px-3 text-sm text-text focus-visible:outline-2 focus-visible:outline-text";

/** A line of the confirmation: one changed field, with the value in force and the one being saved. */
type Change = { field: LimitField; old: number; next: number };

type Pending = {
  changes: LimitsChange;
  rows: Change[];
  /** The new cap, when it is not above the month's spend: the save stops the model at once. */
  belowSpent: number | null;
};

const isLimitField = (name: string): name is LimitField =>
  (LIMIT_FIELDS as readonly string[]).includes(name);

/** The text of a field's fault: the route's own words, with its bounds in them. */
function faultText(fault: LimitFault): string {
  return fault.reason === "out_of_range"
    ? adminReasonText({ reason: "out_of_range", min: fault.min, max: fault.max })
    : adminReasonText({ reason: fault.reason });
}

/** What a failed save says in the dialog when no field explains it. */
function saveErrorText(error: AdminError): string {
  if (error.kind === "reason" || error.kind === "field") return adminReasonText(error);
  return error.status === 0 ? L.limits.saveOffline : L.limits.saveServer;
}

function sourceText(source: LimitSource): string {
  return source.source === "env"
    ? L.limits.sourceEnv
    : L.limits.sourceWeb(source.updated_by_name, formatDateTime(source.updated_at));
}

/** A change as the confirmation writes it: the cap in dollars, the timeout in seconds. */
function valueText(field: LimitField, value: number): string {
  if (field === "cap_usd") return formatUsd(value, true);
  if (field === "timeout_s") return S.admin.llmPage.confirm.seconds(value);
  return formatCount(value);
}

const CHANGE_COLUMNS: Column<Change>[] = [
  { id: "limit", header: L.confirm.colLimit, cell: (row) => L.limits.changeName[row.field] },
  {
    id: "old",
    header: L.confirm.colOld,
    cell: (row) => <span className="text-[#aeb9c6]">{valueText(row.field, row.old)}</span>,
    className: "text-right",
  },
  {
    id: "new",
    header: L.confirm.colNew,
    cell: (row) => <span className="font-semibold">{valueText(row.field, row.next)}</span>,
    className: "text-right",
  },
];

/** The shield of the canvas's fail-closed card. */
function Shield() {
  return (
    <svg
      width="30"
      height="30"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="text-[#fda4af]"
    >
      <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />
      <path d="M12 9v4M12 16v.5" />
    </svg>
  );
}

/** One number field: its label, its bounds and source, a note when the stored value was held to the ceiling, and its fault. */
function LimitInput({
  field,
  limits,
  value,
  fault,
  onChange,
  inputRef,
}: {
  field: LimitField;
  limits: LimitsOut;
  value: string;
  fault: string | undefined;
  onChange: (text: string) => void;
  inputRef: (element: HTMLInputElement | null) => void;
}) {
  const id = useId();
  const bound = limits.bounds[field];
  const source = limits.sources[LIMIT_KEY_OF_FIELD[field]];
  const hintId = `${id}-hint`;
  const clampedId = `${id}-clamped`;
  const faultId = `${id}-fault`;
  const describedBy = [hintId, source.clamped ? clampedId : null, fault ? faultId : null]
    .filter((part) => part !== null)
    .join(" ");
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-[13px] text-[#aeb9c6]">
        {L.limits.field[field]}
      </label>
      <input
        ref={inputRef}
        id={id}
        type="number"
        inputMode="numeric"
        step={1}
        min={bound.min}
        max={bound.max}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-invalid={fault !== undefined ? true : undefined}
        aria-describedby={describedBy}
        className={`${INPUT} ${fault !== undefined ? "border-[#f87171]" : "border-[#2e3a48]"}`}
      />
      <p id={hintId} className="text-xs text-muted">
        {L.limits.rangeHint(bound.min, bound.max)} · {sourceText(source)}
      </p>
      {source.clamped && (
        <p id={clampedId} className="text-xs text-[#fcd9a8]">
          {L.limits.clamped}
        </p>
      )}
      {fault !== undefined && (
        <p id={faultId} className="text-[12.5px] text-[#fda4af]">
          {fault}
        </p>
      )}
    </div>
  );
}

export function LlmLimits({
  limits,
  failClosed,
  spentUsd,
  onSaved,
  onRefetch,
}: {
  /** The effective limits; null when the stored ones cannot be read. */
  limits: LimitsOut | null;
  /** The route said `limits_error`: the panel is read-only. */
  failClosed: boolean;
  /** This month's spend, which a new cap is compared with. */
  spentUsd: number;
  /** A save went through; the page says so. */
  onSaved: () => void;
  /** Read the page again (after a refusal that says the limits could not be read). */
  onRefetch: () => void;
}) {
  const client = useQueryClient();
  const titleId = useId();
  // What the admin typed, by field: only the fields they touched. The rest follow the server's value, so a
  // refresh that brings another admin's save is not hidden behind a stale copy.
  const [edits, setEdits] = useState<Partial<Record<LimitField, string>>>({});
  const [faults, setFaults] = useState<Partial<Record<LimitField, string>>>({});
  const [pending, setPending] = useState<Pending | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  // A request to focus a field, as a new object each time: the effect runs after the dialog that had the
  // focus is gone, so the field keeps it.
  const [focus, setFocus] = useState<{ field: LimitField } | null>(null);
  const inputs = useRef<Partial<Record<LimitField, HTMLInputElement | null>>>({});

  useEffect(() => {
    if (focus !== null) inputs.current[focus.field]?.focus();
  }, [focus]);

  const mutation = useMutation({
    mutationFn: (body: LimitsChange) => putLlmLimits(body),
    onSuccess: async ({ limits: next }) => {
      // What the route answered is what is in force: show it now, in every range the page has read,
      // then read again (the cap and the percentage of the tiles change with it).
      client.setQueriesData<LlmUsage>({ queryKey: adminKeys.llmAll }, (old) =>
        old === undefined ? old : { ...old, limits: next, limits_error: null },
      );
      setEdits({});
      setFaults({});
      setPending(null);
      setDialogError(null);
      onSaved();
      await invalidateAfter(client, "putLlmLimits");
    },
    onError: (error) => {
      const failure = adminErrorOf(error);
      if (failure.kind === "field" && isLimitField(failure.field)) {
        const { field } = failure;
        setFaults((before) => ({ ...before, [field]: adminReasonText(failure) }));
        setPending(null);
        setFocus({ field });
        // The bounds on screen may be out of date (the job lock's ceiling moved under the form): read them again.
        if (failure.reason === "out_of_range") onRefetch();
        return;
      }
      setDialogError(saveErrorText(failure));
      if (failure.kind === "reason" && failure.reason === "limits_unavailable") onRefetch();
    },
  });

  if (failClosed || limits === null) {
    return (
      <section aria-labelledby={titleId} className={`${PANEL} border-[#5a2e36]`}>
        <h2 id={titleId} className="text-[15px] font-semibold">
          {L.limits.title}
        </h2>
        <Shield />
        <h3 className="text-[17px] font-semibold">{L.failClosed.title}</h3>
        <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{L.failClosed.body}</p>
      </section>
    );
  }

  const { changes, errors } = limitChanges(limits, edits);
  const canSave = Object.keys(changes).length > 0 || Object.keys(errors).length > 0;

  const save = () => {
    const bad = LIMIT_FIELDS.filter((field) => errors[field] !== undefined);
    const first = bad[0];
    if (first !== undefined) {
      setFaults(
        Object.fromEntries(
          bad.flatMap((field) => {
            const fault = errors[field];
            return fault === undefined ? [] : [[field, faultText(fault)]];
          }),
        ),
      );
      setFocus({ field: first });
      return;
    }
    const rows = LIMIT_FIELDS.flatMap((field): Change[] => {
      const next = changes[field];
      return next === undefined ? [] : [{ field, old: limits[field], next }];
    });
    if (rows.length === 0) return;
    const newCap = changes.cap_usd;
    setDialogError(null);
    setPending({
      changes,
      rows,
      belowSpent: newCap !== undefined && spentUsd >= newCap ? newCap : null,
    });
  };

  const edit = (field: LimitField, text: string) => {
    setEdits((before) => ({ ...before, [field]: text }));
    setFaults((before) => {
      const rest = { ...before };
      delete rest[field];
      return rest;
    });
  };

  let warning: ReactNode = null;
  if (pending !== null && pending.belowSpent !== null) {
    warning = (
      <div
        role="alert"
        className="rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-3 text-[13.5px] leading-snug text-[#fcd9a8]"
      >
        {L.confirm.belowSpent(formatUsd(pending.belowSpent, true), formatUsd(spentUsd))}
      </div>
    );
  }

  return (
    <section aria-labelledby={titleId} className={`${PANEL} border-[#3a4757]`}>
      <h2 id={titleId} className="text-[15px] font-semibold">
        {L.limits.title}
      </h2>
      <form
        noValidate
        className="flex flex-col gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          save();
        }}
      >
        {LIMIT_FIELDS.map((field) => (
          <LimitInput
            key={field}
            field={field}
            limits={limits}
            value={edits[field] ?? String(limits[field])}
            fault={faults[field]}
            onChange={(text) => edit(field, text)}
            inputRef={(element) => {
              inputs.current[field] = element;
            }}
          />
        ))}
        <button
          type="submit"
          disabled={!canSave}
          className="h-11 rounded-lg bg-blue-600 text-[15px] font-semibold text-white hover:bg-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-50"
        >
          {L.limits.save}
        </button>
        <p className="text-xs leading-relaxed text-muted">{L.limits.note}</p>
      </form>
      {pending !== null && (
        <ConfirmDialog
          title={L.confirm.title}
          confirmLabel={pending.belowSpent === null ? L.confirm.confirm : L.confirm.confirmAnyway}
          tone={pending.belowSpent === null ? "primary" : "danger"}
          busy={mutation.isPending}
          error={dialogError}
          onConfirm={() => mutation.mutate(pending.changes)}
          onCancel={() => setPending(null)}
        >
          <DataTable
            label={L.confirm.tableLabel}
            columns={CHANGE_COLUMNS}
            rows={pending.rows}
            rowKey={(row) => row.field}
          />
          {warning}
          <p className="text-xs leading-relaxed text-[#aeb9c6]">{L.confirm.note}</p>
        </ConfirmDialog>
      )}
    </section>
  );
}
