// The audit page's view (the four filters of spec §4.7) as URL search params, so a reload and a link shared
// to another tab keep it (spec §3), and the reading of a failed read: what a 422, a 503 and a 403 each mean
// for this page. Only what differs from the default is written, and only what is understood is read: a range
// or a group the server does not offer is dropped here, so it is never sent, and an empty or blank text
// filter is never sent either (the handler answers 422 to an empty one).
//
// The cursor is not in the URL. The API pages forward only (`audit_id < cursor`), so "Trước" needs the
// cursors of the pages already seen, which the page keeps in its own state and drops when a filter changes.
import {
  ADMIN_RANGES,
  AUDIT_GROUPS,
  adminErrorOf,
  type AdminRange,
  type AuditGroup,
} from "../../api/admin";
import { ApiError } from "../../api/client";

/** The range the handler uses when none is sent, and so the one the URL leaves out. */
export const DEFAULT_RANGE: AdminRange = "7d";

/** The rows of a page: the server's own default and the number the page's "1–50" counts from. */
export const PAGE_SIZE = 50;

/** The four filters of the form. */
export const FILTER_FIELDS = ["range", "group", "actor", "subject"] as const;
export type FilterField = (typeof FILTER_FIELDS)[number];

export type AuditView = {
  range: AdminRange;
  group?: AuditGroup;
  /** A username, or `system` or `llm`. Never empty. */
  actor?: string;
  /** An exact `subject_id`. Never empty. */
  subject?: string;
};

const isFilterField = (value: unknown): value is FilterField =>
  typeof value === "string" && (FILTER_FIELDS as readonly string[]).includes(value);

/** The trimmed text of a param, or undefined when it is missing, empty or blank. */
function text(params: URLSearchParams, key: string): string | undefined {
  const value = params.get(key)?.trim();
  return value ? value : undefined;
}

export function readView(params: URLSearchParams): AuditView {
  const view: AuditView = {
    range: ADMIN_RANGES.find((range) => range === params.get("range")) ?? DEFAULT_RANGE,
  };
  const group = AUDIT_GROUPS.find((candidate) => candidate === params.get("group"));
  if (group !== undefined) view.group = group;
  const actor = text(params, "actor");
  if (actor !== undefined) view.actor = actor;
  const subject = text(params, "subject");
  if (subject !== undefined) view.subject = subject;
  return view;
}

/** The URL's params for a view, in a fixed order: the default range and an empty text are left out. */
export function viewToParams(view: AuditView): URLSearchParams {
  const params = new URLSearchParams();
  if (view.range !== DEFAULT_RANGE) params.set("range", view.range);
  if (view.group) params.set("group", view.group);
  if (view.actor) params.set("actor", view.actor);
  if (view.subject) params.set("subject", view.subject);
  return params;
}

/** One string for a view, equal for equal views: the key of the page's cursors, and what the URL holds. */
export const viewKey = (view: AuditView): string => viewToParams(view).toString();

/**
 * Some filter hides events: a group, an actor or a subject is set, or the range is narrower than the default.
 * A range as wide as the default or wider hides nothing a person would call a filter, so an empty answer under
 * it is an empty log, not "no match".
 */
export function isFiltered(view: AuditView): boolean {
  return (
    view.group !== undefined ||
    Boolean(view.actor) ||
    Boolean(view.subject) ||
    ADMIN_RANGES.indexOf(view.range) < ADMIN_RANGES.indexOf(DEFAULT_RANGE)
  );
}

/**
 * What a failed read of the log says, by what the page does about it:
 * - `filter`: a 422 that names one of the four filters, shown under that filter;
 * - `filters`: a 422 that names none of them (the cursor, the limit, or a shape this client does not know);
 * - `timeout` and `query_failed`: the two 503 reasons, shown above the table, with the filters still open
 *   so they can be narrowed;
 * - `forbidden`: a 403, the card of a role that is not admin any more;
 * - `load`: anything else (a 5xx, a 404, the network): the page's own error; `status` is 0 with no answer.
 */
export type AuditFault =
  | { kind: "filter"; field: FilterField }
  | { kind: "filters" }
  | { kind: "timeout" }
  | { kind: "query_failed" }
  | { kind: "forbidden" }
  | { kind: "load"; status: number };

/** The name FastAPI's validation gives (`loc: ["query", name]`) in one entry of its list, or null. */
function queryNameOf(entry: unknown): string | null {
  if (typeof entry !== "object" || entry === null) return null;
  const loc = (entry as { loc?: unknown }).loc;
  if (!Array.isArray(loc) || loc[0] !== "query") return null;
  return typeof loc[1] === "string" ? loc[1] : null;
}

/** The fault of a 422: FastAPI's list names the filter in `loc`; the house shape `{field, reason}` in `field`. */
function unprocessable(error: unknown): AuditFault {
  const failure = adminErrorOf(error);
  if (failure.kind === "field") {
    return isFilterField(failure.field)
      ? { kind: "filter", field: failure.field }
      : { kind: "filters" };
  }
  const detail = error instanceof ApiError ? error.detail : null;
  if (Array.isArray(detail)) {
    for (const entry of detail) {
      const name = queryNameOf(entry);
      if (isFilterField(name)) return { kind: "filter", field: name };
    }
  }
  return { kind: "filters" };
}

export function auditFaultOf(error: unknown): AuditFault {
  const failure = adminErrorOf(error);
  if (failure.status === 403) return { kind: "forbidden" };
  if (failure.status === 422) return unprocessable(error);
  if (failure.status === 503 && failure.kind === "reason") {
    if (failure.reason === "timeout") return { kind: "timeout" };
    if (failure.reason === "query_failed") return { kind: "query_failed" };
  }
  return { kind: "load", status: failure.status };
}
