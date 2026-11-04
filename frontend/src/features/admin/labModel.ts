// The pure parts of the lab pages (P14-T10): the time the create form takes and sends, what the form checks before it
// posts, the words of a 422 beside its field, and the counter after a label. No component, no request.
import type { InfiniteData } from "@tanstack/react-query";
import {
  LAB_LIMITS,
  type LabAlertsResponse,
  type LabError,
  type LabField,
  type LabFieldReason,
  type LabLabel,
  type LabPurpose,
  type NewLabRun,
} from "../../api/admin";
import { S } from "../../strings";

// --- the time the form takes ----------------------------------------------------------------------------------------

/**
 * The offset of `DISPLAY_TZ` (format.ts), the zone every time on the console is shown in. Asia/Ho_Chi_Minh has had
 * no daylight saving since 1975, so the offset is one number; labModel.test.ts holds it equal to what Intl says
 * for the zone. The form's times are entered in the console's zone, not the browser's: a run typed as 09:00 is
 * shown as 09:00 in the table, wherever the admin's browser is.
 */
export const DISPLAY_OFFSET = "+07:00";

// A browser gives `2026-11-04T09:30`, with seconds when it has some (`:45`), and with milliseconds (`.000`) in a few
// engines (jsdom among them) and for a step under a second.
const LOCAL = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::(\d{2})(\.\d{3})?)?$/;

/**
 * What a `datetime-local` input holds (`2026-11-04T09:30`, or with seconds), as the ISO 8601 text with the offset
 * that `POST /api/admin/lab/runs` asks for; null when it is not a time. An empty input is null too: the caller
 * tells empty from unreadable.
 */
export function localInputToIso(value: string): string | null {
  const match = LOCAL.exec(value);
  if (match === null) return null;
  const iso = `${match[1]}T${match[2]}:${match[3] ?? "00"}${match[4] ?? ""}${DISPLAY_OFFSET}`;
  return Number.isNaN(new Date(iso).getTime()) ? null : iso;
}

// --- the create form ------------------------------------------------------------------------------------------------

/** What is typed in the form, as the controls hold it. The purpose has no default: it decides what the run is scored as. */
export type NewRunValues = {
  name: string;
  purpose: LabPurpose | null;
  starts: string;
  ends: string;
};

/** The inputs of the form, by the name the server gives them in a 422. */
export const NEW_RUN_FIELDS = ["name", "purpose", "starts_at", "ends_at"] as const;
export type NewRunField = (typeof NEW_RUN_FIELDS)[number];

export function isNewRunField(field: string): field is NewRunField {
  return (NEW_RUN_FIELDS as readonly string[]).includes(field);
}

export type NewRunErrors = Partial<Record<NewRunField, LabFieldReason>>;

/**
 * What the server would refuse without looking at the database, and what cannot be sent at all: no name, a name over
 * the limit, no purpose, a time that is empty or that the browser could not give a value for. It does not judge the
 * order of the two times nor the years: the server answers those (`not_after_starts`, `invalid`), and the page shows
 * its answer.
 */
export function checkNewRun(values: NewRunValues): NewRunErrors {
  const errors: NewRunErrors = {};
  const name = values.name.trim();
  if (name === "") errors.name = "empty";
  // Characters, as the server counts them (`len` of a Python string), not UTF-16 units.
  else if ([...name].length > LAB_LIMITS.nameMax) errors.name = "too_long";
  if (values.purpose === null) errors.purpose = "required";
  const timeFault = (value: string): LabFieldReason | undefined =>
    value === "" ? "required" : localInputToIso(value) === null ? "invalid" : undefined;
  const starts = timeFault(values.starts);
  const ends = timeFault(values.ends);
  if (starts !== undefined) errors.starts_at = starts;
  if (ends !== undefined) errors.ends_at = ends;
  return errors;
}

/** The body of `POST /api/admin/lab/runs`, or null while the form is not complete. */
export function newRunBody(values: NewRunValues): NewLabRun | null {
  const starts = localInputToIso(values.starts);
  const ends = localInputToIso(values.ends);
  if (values.purpose === null || starts === null || ends === null) return null;
  return { name: values.name.trim(), purpose: values.purpose, starts_at: starts, ends_at: ends };
}

/**
 * The words of a 422 `{field, reason}`, shown beside the input it names. `invalid` is worded by the input (a time
 * says the years the server allows); the whole-request `body` and any pair the page has no words for are the
 * console's generic text.
 */
export function labFieldText(field: LabField, reason: LabFieldReason): string {
  const T = S.admin.lab.fieldReason;
  if (field === "body") return S.common.unknownError;
  if (field === "label") return T.invalidLabel;
  switch (reason) {
    case "required":
      return field === "purpose" ? T.requiredPurpose : T.required;
    case "empty":
      return T.empty;
    case "too_long":
      return T.tooLong(LAB_LIMITS.nameMax);
    case "taken":
      return T.taken;
    case "not_after_starts":
      return T.not_after_starts;
    case "invalid":
      if (field === "name") return T.invalidName;
      if (field === "purpose") return T.invalidPurpose;
      return T.invalidTime(LAB_LIMITS.yearMin, LAB_LIMITS.yearMax);
  }
}

/**
 * The words on an alert's row for a label the server refused: the two 409s and the 404 of the label routes, and a
 * 422 on the label. Anything else is the console's generic text; a code is never shown.
 */
export function labRowErrorText(error: LabError): string {
  const R = S.admin.lab.runPage.rowError;
  switch (error.kind) {
    case "not_a_queue_head":
      return R.not_a_queue_head;
    case "outside_every_run":
      return R.outside_every_run;
    case "not_found":
      return R.not_found;
    case "field":
      return error.field === "label"
        ? labFieldText(error.field, error.reason)
        : S.common.unknownError;
    default:
      return S.common.unknownError;
  }
}

// --- the counter after a label --------------------------------------------------------------------------------------

/**
 * The pages of a run's alerts as the cache holds them, with `alertId` carrying `label` (null: none) once the server
 * has said so, and the counter of the first page's run moved by the one label that was added or removed. The counter
 * is read from the first page's `run` only, so the later pages' copies are left as they came. An alert that no
 * page holds changes nothing, and the same data comes back. `data` is not changed.
 */
export function withLabel(
  data: InfiniteData<LabAlertsResponse, string | null>,
  alertId: string,
  label: LabLabel | null,
): InfiniteData<LabAlertsResponse, string | null> {
  for (const [pageAt, page] of data.pages.entries()) {
    const alertAt = page.alerts.findIndex((alert) => alert.alert_id === alertId);
    const before = page.alerts[alertAt];
    if (before === undefined) continue;
    const delta = (label === null ? 0 : 1) - (before.label === null ? 0 : 1);
    const pages = data.pages.map((each, index) => {
      let next = each;
      if (index === pageAt) {
        next = {
          ...next,
          alerts: next.alerts.map((alert, at) => (at === alertAt ? { ...alert, label } : alert)),
        };
      }
      if (index === 0 && delta !== 0) {
        next = {
          ...next,
          run: { ...next.run, labelled: Math.max(0, next.run.labelled + delta) },
        };
      }
      return next;
    });
    return { ...data, pages };
  }
  return data;
}
