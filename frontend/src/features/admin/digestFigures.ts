// The pure helpers of the digest page (P11-T15, spec §4.5): a day in a sentence, the span of a cluster, the tail
// of an alert id, the counts of the summary line, the check for a refused day, and the swap of one row of the
// answer. No React here; the page shows them (DigestPage.tsx) and digestFigures.test.ts pins them.
import { adminErrorOf, type DigestResponse, type DigestRow } from "../../api/admin";
import { formatClock, formatDateTime, formatTime } from "../../format";

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * A day of the server (`YYYY-MM-DD`, in the display zone) as `dd/mm/yyyy`. It is only re-ordered: no `Date` is
 * made of it, so the browser's zone cannot move it. Anything that is not a day is shown as it came.
 */
export function formatDay(day: string): string {
  const parts = DAY.exec(day);
  return parts === null ? day : `${parts[3]}/${parts[2]}/${parts[1]}`;
}

const LOCAL_DAY = /^\d{2}\/\d{2}\/\d{4} /;

/**
 * The time span of a cluster: `08:02 – 17:40` when both ends fall on one day of the display zone (the page
 * already says which day), and `29/09 23:50 – 30/09 00:10` when it crosses midnight. A missing end is a dash
 * and an unreadable one is shown as it came (`format.ts`).
 */
export function spanText(first: string, last: string): string {
  const a = formatDateTime(first);
  const b = formatDateTime(last);
  const sameDay = LOCAL_DAY.test(a) && LOCAL_DAY.test(b) && a.slice(0, 10) === b.slice(0, 10);
  return sameDay
    ? `${formatClock(first)} – ${formatClock(last)}`
    : `${formatTime(first)} – ${formatTime(last)}`;
}

/** An alert id is `<epoch>.<n>`; a sentence names the cluster by `…<n>`. An id with no such tail is shown whole. */
export function alertTail(id: string): string {
  const dot = id.lastIndexOf(".");
  return dot >= 0 && dot < id.length - 1 ? `…${id.slice(dot + 1)}` : id;
}

export type DigestSummary = {
  clusters: number;
  reviewed: number;
  waiting: number;
  disagreements: number;
};

/**
 * The summary line, counted from the rows the list shows. A cluster a "Sai" review reopened stays on the list
 * with its verdict (the route keeps it there), so it is counted as reviewed; the disagreements are every row ①
 * did not suggest closing, reviewed or not.
 */
export function summarise(rows: readonly DigestRow[]): DigestSummary {
  const reviewed = rows.filter((row) => row.reviewed_verdict !== null).length;
  return {
    clusters: rows.length,
    reviewed,
    waiting: rows.length - reviewed,
    disagreements: rows.filter((row) => row.disagreement).length,
  };
}

/** The answer `GET /api/admin/digest?day=` gives for a day it cannot read: `422 {reason: "bad_day"}`. */
export function isBadDay(error: unknown): boolean {
  const failure = adminErrorOf(error);
  return failure.kind === "reason" && failure.reason === "bad_day" && failure.status === 422;
}

/** `data` with the row of the same alert replaced by `row`. An answer that does not hold the alert is as it was. */
export function withRow(data: DigestResponse, row: DigestRow): DigestResponse {
  if (!data.rows.some((r) => r.alert_id === row.alert_id)) return data;
  return { ...data, rows: data.rows.map((r) => (r.alert_id === row.alert_id ? row : r)) };
}

/**
 * The row a review recorded. The review answers `{row, reopened}`: when it says it reopened the alert, the row
 * says so too, whatever flag the row itself carried.
 */
export function markReopened(row: DigestRow, reopened: boolean): DigestRow {
  return reopened && !row.reopened_by_review ? { ...row, reopened_by_review: true } : row;
}
