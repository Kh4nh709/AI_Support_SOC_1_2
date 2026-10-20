// The arithmetic of the overview page (P11-T11, spec §4.1), apart from React so that a test can state each rule
// on its own:
//   - the API lists only the days and the statuses that occur, so the series and the funnel are zero-filled;
//   - a section that failed (`null`, with an entry in `errors[]`) is told from one that is merely empty;
//   - the failing health checks come first;
//   - the numbers are written the Vietnamese way (the canvas: "7.040", "$0,51", "1,7%").
// Every time goes through `format.ts`; a day (`YYYY-MM-DD`) is a calendar day of the display zone, not an instant.
import type {
  AdminError,
  AdminRange,
  FailedJob,
  HealthCheck,
  OverviewResponse,
  OverviewSection,
} from "../../api/admin";
import { formatDateTime } from "../../format";
import { S, adminReasonText } from "../../strings";

/** Most failed jobs the server sends (`_FAILED_JOBS_LIMIT` of admin_overview.py; a test compares them). */
export const FAILED_JOBS_CAP = 50;

/** How many days back each range reaches (`_WINDOWS` of admin_overview.py; a test compares them). */
export const WINDOW_DAYS: Record<AdminRange, number> = { "24h": 1, "7d": 7, "30d": 30 };

const DAY_MS = 86_400_000;
/** More days than any range (31) plus the slack of a clock that is a few days off: beyond it, nothing is filled. */
const MAX_SPAN_DAYS = 62;

export type DayPoint = { day: string; total: number; heads: number; duplicates: number };

// --- days -----------------------------------------------------------------------------------------------------

const ISO_DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** The number of days since the epoch of a `YYYY-MM-DD`, or null for any other text. */
function dayNumber(day: string): number | null {
  const m = ISO_DAY.exec(day);
  if (m === null) return null;
  const n = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) / DAY_MS;
  return Number.isFinite(n) ? n : null;
}

const dayOfNumber = (n: number): string => new Date(n * DAY_MS).toISOString().slice(0, 10);

/** The calendar day of an instant in the display zone: `2026-10-01` for 00:30 on 1 October in Ho Chi Minh. */
export function localDay(ms: number): string {
  // `formatDateTime` is the one place that knows the zone: "30/09/2026 09:40:02".
  const [day, month, year] = formatDateTime(new Date(ms).toISOString()).slice(0, 10).split("/");
  return `${year}-${month}-${day}`;
}

/** A day moved by whole days (the display zone has no daylight saving, so a day is a day). */
export function shiftDay(day: string, by: number): string {
  const n = dayNumber(day);
  return n === null ? day : dayOfNumber(n + by);
}

/** `30/09`, the canvas's label under a bar. A text that is not a day is shown as it came. */
export function dayLabel(day: string): string {
  if (day === "") return S.common.missing;
  const m = ISO_DAY.exec(day);
  return m === null ? day : `${m[3]}/${m[2]}`;
}

/**
 * The series of days of the range, oldest first, one point for each local day the window touches
 * (24h: today and yesterday; 7d: 8 days; 30d: 31), with 0 for a day the API left out. A day the API sent is
 * never dropped: if the browser's clock is off, the series is stretched to hold it; and if the clock and the
 * data are so far apart that filling would build a huge list, the API's own days are returned as they are.
 */
export function zeroFillDays(
  days: readonly DayPoint[],
  range: AdminRange,
  nowMs: number,
): DayPoint[] {
  const byDay = new Map<string, DayPoint>();
  for (const point of days) byDay.set(point.day, point);
  const given = [...byDay.keys()].sort();
  const asGiven = given.flatMap((key) => byDay.get(key) ?? []);
  if (!Number.isFinite(nowMs)) return asGiven;

  const end = localDay(nowMs);
  const start = localDay(nowMs - WINDOW_DAYS[range] * DAY_MS);
  const first = given[0];
  const last = given[given.length - 1];
  const from = dayNumber(first !== undefined && first < start ? first : start);
  const to = dayNumber(last !== undefined && last > end ? last : end);
  if (from === null || to === null || to - from > MAX_SPAN_DAYS) return asGiven;

  const filled: DayPoint[] = [];
  for (let n = from; n <= to; n += 1) {
    const day = dayOfNumber(n);
    filled.push(byDay.get(day) ?? { day, total: 0, heads: 0, duplicates: 0 });
  }
  return given.every((key) => filled.some((point) => point.day === key)) ? filled : asGiven;
}

// --- the funnel -----------------------------------------------------------------------------------------------

type Funnel = NonNullable<OverviewResponse["funnel"]>;

/**
 * The five status rows of the canvas's "Tình trạng xử lý", in its order: the statuses of `alerts.status` each
 * one adds up (`closed_by_tier1` is the three ways Tier 1 closes a head). The sixth row, ① coverage, is
 * `ready / heads`.
 */
export const FUNNEL_STEPS = [
  { key: "auto_closed", statuses: ["auto_closed"] },
  { key: "waiting", statuses: ["queued_tier1"] },
  { key: "active", statuses: ["tier1_active"] },
  { key: "closed_by_tier1", statuses: ["closed_fp", "closed_benign", "closed_confirmed"] },
  { key: "escalated", statuses: ["escalated_tier2"] },
] as const;
export type FunnelKey = (typeof FUNNEL_STEPS)[number]["key"];

/** The count under `key`, 0 when the API left it out. Only the object's own keys count: never the prototype's. */
function countOf(counts: Readonly<Record<string, number>>, key: string): number {
  if (!Object.hasOwn(counts, key)) return 0;
  const n = counts[key];
  return typeof n === "number" && Number.isFinite(n) ? n : 0;
}

export function funnelCounts(funnel: Funnel): {
  steps: { key: FunnelKey; count: number }[];
  /** Heads with a ① suggestion ready. */
  ready: number;
  /** Every head of the range, in whatever status (a head being enriched has no row of its own). */
  heads: number;
} {
  const steps = FUNNEL_STEPS.map((step) => ({
    key: step.key,
    count: step.statuses.reduce((sum, status) => sum + countOf(funnel.by_status, status), 0),
  }));
  const heads = Object.keys(funnel.by_status).reduce(
    (sum, status) => sum + countOf(funnel.by_status, status),
    0,
  );
  return { steps, ready: countOf(funnel.triage, "ready"), heads };
}

// --- health, jobs, failed sections --------------------------------------------------------------------------

/** The failing checks first, then the ones that are fine; each group keeps the order the server sent. */
export function failedFirst(checks: readonly HealthCheck[]): HealthCheck[] {
  return [...checks.filter((c) => !c.ok), ...checks.filter((c) => c.ok)];
}

/** When a failed job last ran: `locked_at` (stamped on every attempt), or its creation if it never ran. */
export function lastAttemptAt(job: FailedJob): string {
  return job.locked_at ?? job.created_at;
}

export type SectionFailure = "timeout" | "query_failed" | "unknown";

/**
 * Whether a section of the overview failed, and why: null when it has data (a `0` is data, and so is an empty
 * list). A section that is `null` has an entry in `errors[]` with its code; one with no entry, or a code this
 * page has no text for, is `unknown`. The health row is the one section that is `null` without an error: no
 * check has run yet.
 */
export function sectionFailure(
  data: OverviewResponse,
  section: OverviewSection,
): SectionFailure | null {
  if (data[section] !== null && data[section] !== undefined) return null;
  const entry = (Array.isArray(data.errors) ? data.errors : []).find((e) => e.section === section);
  if (entry === undefined) return section === "health" ? null : "unknown";
  return entry.error === "timeout" || entry.error === "query_failed" ? entry.error : "unknown";
}

// --- the cost card -------------------------------------------------------------------------------------------

/** The overview's `llm_month` when it was served (the section is `null` when its own query failed). */
export type LlmMonth = NonNullable<OverviewResponse["llm_month"]>;

/**
 * What the cost card says about the month (DEC-203, P11-T20 row 50):
 *   - `unknown`: the limits could not be read, so there is no cap to compare with (read-only, the LLM page's
 *     "không đọc được hạn mức"); a cap with no `pct` is told the same way, as the card has no share to print;
 *   - `stopped`: the spend has reached the cap, `spent_usd >= cap_usd`, the adapter's own comparison. Never
 *     `pct`, which the route rounds to one decimal: it can read 99,9 at the cap and 100 a cent under it;
 *   - `ok`: under the cap, with the share the route computed.
 */
export type LlmCardState = "ok" | "stopped" | "unknown";

export function llmCardState(month: LlmMonth): LlmCardState {
  if (month.cap_usd === null) return "unknown";
  if (month.spent_usd >= month.cap_usd) return "stopped";
  return month.pct === null ? "unknown" : "ok";
}

// --- a write that was refused -------------------------------------------------------------------------------

/**
 * The text of a refused write, for its dialog: the Vietnamese of a reason this client knows (`forbidden`,
 * `already_queued`, ...), and "Có lỗi xảy ra" for anything else, a 5xx and the network included. The server's
 * English `detail` of those is for a log, not for the admin.
 */
export function writeErrorText(error: AdminError): string {
  return error.kind === "reason" || error.kind === "field"
    ? adminReasonText(error)
    : S.common.unknownError;
}

// --- numbers --------------------------------------------------------------------------------------------------

const COUNT = new Intl.NumberFormat("vi-VN");
const SPEND = new Intl.NumberFormat("vi-VN", {
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});
const CAP = new Intl.NumberFormat("vi-VN", { maximumFractionDigits: 2 });
const PCT = new Intl.NumberFormat("vi-VN", { minimumFractionDigits: 1, maximumFractionDigits: 1 });

/** `7.040`: a count with the Vietnamese thousands dot. */
export const formatCount = (n: number): string => COUNT.format(n);
/** `$0,51`: what has been spent, in cents. */
export const formatSpend = (n: number): string => `$${SPEND.format(n)}`;
/** `$30`: the cap, with cents only when it has them. */
export const formatCap = (n: number): string => `$${CAP.format(n)}`;
/** `1,7%`: the share of the cap, to one decimal as the server floors it. */
export const formatPct = (n: number): string => `${PCT.format(n)}%`;
