// The pure figures of the LLM page (spec §4.3): how money and counts are written, which state the cost tile
// is in, what the pipeline table sums to, how a pipeline and a subject are named, and how a field of the
// limits form is read. Nothing here fetches or renders; `LlmPage.tsx` shows them and `llmFigures.test.ts`
// pins them. Numbers are written the Vietnamese way: a point groups thousands, a comma starts the decimals.
import type {
  LimitField,
  LimitsChange,
  LimitsOut,
  LlmUsage,
  PipelineRoleRow,
} from "../../api/admin";
import { LIMIT_FIELDS } from "../../api/admin";
import { S } from "../../strings";

const MISSING = S.common.missing;

const number = (maximumFractionDigits: number, minimumFractionDigits = 0) =>
  new Intl.NumberFormat("vi-VN", { minimumFractionDigits, maximumFractionDigits });

const COUNT = number(0);
const MONEY = number(4, 2);
const WHOLE_MONEY = number(0);
const PERCENT = number(1);
const MILLIONS = number(2);
const SECONDS = number(1, 1);

/** "1.589". */
export function formatCount(value: number): string {
  return COUNT.format(value);
}

/**
 * "$0,51", "$0,0024", "$24,60": two to four decimals, as `llm_runs.cost_usd` and the month's spend carry
 * (the route rounds them to four). With `whole`, no decimals: the cap is an integer ("$30").
 */
export function formatUsd(value: number, whole = false): string {
  return `$${(whole ? WHOLE_MONEY : MONEY).format(value)}`;
}

/** "2,44 tr" from 100,000 tokens up, in millions with at most two decimals; "47.000" below. */
export function formatTokens(value: number): string {
  return value >= 100_000 ? `${MILLIONS.format(value / 1_000_000)} tr` : COUNT.format(value);
}

/** "82%", "82,4%": one decimal at most (`pct` is floored to one by the route). */
export function formatPercent(value: number): string {
  return `${PERCENT.format(value)}%`;
}

/** "2,3 s", "1,0 s": milliseconds as seconds with one decimal, so a column lines up; a missing latency is a dash. */
export function formatSeconds(milliseconds: number | null): string {
  return milliseconds === null ? MISSING : `${SECONDS.format(milliseconds / 1000)} s`;
}

/** "2,4 s / 9,8 s": p50 over p95. Both missing is one dash. */
export function formatLatency(p50: number | null, p95: number | null): string {
  if (p50 === null && p95 === null) return MISSING;
  return `${formatSeconds(p50)} / ${formatSeconds(p95)}`;
}

// --- the cost tile ------------------------------------------------------------------------------------------

/** The percentage of the cap from which the cost turns amber. */
export const WARN_PCT = 80;

export type CostState = "ok" | "warn" | "stopped";

/**
 * `stopped` when the month's spend has reached the cap: `spent_usd >= cap_usd`, the adapter's own comparison,
 * and never `pct`, which the route floors to one decimal (P11-T04 review m1, P11-T20). `warn` from
 * `WARN_PCT` of the cap and below it. With no cap (the limits could not be read) there is nothing to compare
 * with, and the tile is `ok`.
 */
export function costState(month: LlmUsage["month"]): CostState {
  if (month.cap_usd !== null && month.spent_usd >= month.cap_usd) return "stopped";
  if (month.pct !== null && month.pct >= WARN_PCT) return "warn";
  return "ok";
}

// --- the pipeline table ------------------------------------------------------------------------------------

/** `stopped_by` -> count as `[code, count]`, the largest count first, then by code. */
export function stoppedEntries(stopped: Readonly<Record<string, number>>): [string, number][] {
  return Object.entries(stopped).sort(([a, x], [b, y]) => y - x || a.localeCompare(b));
}

export type PipelineSum = { pipeline: string; calls: number; inputTokens: number };

export type RangeSummary = {
  calls: number;
  /**
   * Calls of every row but the ① verifier's: one per ① alert run and one per ② run, the denominator of
   * `stopped`. (`calls` is every call, the verifier's too.)
   */
  runs: number;
  inputTokens: number;
  outputTokens: number;
  /** ① (`triage`) first, ② (`investigate`) second, any other pipeline after, in the order they came. */
  byPipeline: PipelineSum[];
  /**
   * Runs with a `stopped_by`, over the rows `runs` counts. A ① verifier failure writes `stopped_by` on the
   * verifier's row and on the proposer's, so the verifier's rows are left out: one failed alert is one stop
   * (P11-T13 review m1).
   */
  stopped: number;
  /** The `stopped_by` most runs stopped on, over the same rows; null when none stopped. */
  mainStopped: { code: string; count: number } | null;
};

const PIPELINE_ORDER = ["triage", "investigate"];

/** The sums the four tiles read, over the rows of `by_pipeline_role`. */
export function summarise(rows: readonly PipelineRoleRow[]): RangeSummary {
  let calls = 0;
  let runs = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let stopped = 0;
  const perPipeline = new Map<string, PipelineSum>();
  const perReason = new Map<string, number>();
  for (const row of rows) {
    calls += row.calls;
    inputTokens += row.input_tokens;
    outputTokens += row.output_tokens;
    const sum = perPipeline.get(row.pipeline) ?? {
      pipeline: row.pipeline,
      calls: 0,
      inputTokens: 0,
    };
    sum.calls += row.calls;
    sum.inputTokens += row.input_tokens;
    perPipeline.set(row.pipeline, sum);
    // The verifier's row repeats the stop its proposer's row already carries: it is not a run of its own.
    if (row.role === "verifier") continue;
    runs += row.calls;
    for (const [code, count] of Object.entries(row.stopped)) {
      stopped += count;
      perReason.set(code, (perReason.get(code) ?? 0) + count);
    }
  }
  const rank = (pipeline: string) => {
    const index = PIPELINE_ORDER.indexOf(pipeline);
    return index === -1 ? PIPELINE_ORDER.length : index;
  };
  // A stable sort: the pipelines outside the two keep the order they came in.
  const byPipeline = [...perPipeline.values()].sort((a, b) => rank(a.pipeline) - rank(b.pipeline));
  const [main] = stoppedEntries(Object.fromEntries(perReason));
  return {
    calls,
    runs,
    inputTokens,
    outputTokens,
    byPipeline,
    stopped,
    mainStopped: main === undefined ? null : { code: main[0], count: main[1] },
  };
}

const own = (table: object, key: string) => Object.hasOwn(table, key);

/**
 * The name of a `(pipeline, role)` row: "① triage · proposer", "① triage · verifier", "② điều tra case". A
 * pipeline or role this page has no word for is shown as it came ("chat · assistant").
 */
export function pipelineLabel(pipeline: string, role: string | null): string {
  const names = S.admin.llmPage.pipeline;
  if (pipeline === "investigate") return names.investigateRow;
  if (pipeline === "triage") {
    if (role === null) return names.triageNoRole;
    return own(names.triageRole, role)
      ? names.triageRole[role as keyof typeof names.triageRole]
      : `${names.triageNoRole} · ${role}`;
  }
  return role === null ? pipeline : `${pipeline} · ${role}`;
}

/** The short mark of a pipeline for a sentence ("①", "②"), or the pipeline as it came. */
export function pipelineMark(pipeline: string): string {
  const names = S.admin.llmPage.pipeline;
  if (pipeline === "triage") return names.triage;
  if (pipeline === "investigate") return names.investigate;
  return pipeline;
}

// --- the recent calls --------------------------------------------------------------------------------------

/** The page a run's subject has: an alert or a case. Nothing else has one, and no id means no link. */
export function subjectLink(type: string | null, id: string | null): string | null {
  if (id === null || id === "") return null;
  if (type === "alert") return `/alerts/${encodeURIComponent(id)}`;
  if (type === "case") return `/cases/${encodeURIComponent(id)}`;
  return null;
}

const LONG_ID = 12;
const TAIL = 8;

/** An id of more than twelve characters is shown as "…" and its last eight; the link and `title` carry it whole. */
export function shortId(id: string): string {
  return id.length > LONG_ID ? `…${id.slice(-TAIL)}` : id;
}

// --- the limits form ---------------------------------------------------------------------------------------

/** What is wrong with a field: the reasons of the route's 422 (`not_integer`, `out_of_range`) and `empty`. */
export type LimitFault =
  | { ok: false; reason: "empty" }
  | { ok: false; reason: "not_integer" }
  | { ok: false; reason: "out_of_range"; min: number; max: number };

export type LimitParse = { ok: true; value: number } | LimitFault;

/** Looks like a number: a sign, digits, a decimal part, an exponent. Hex, `Infinity` and `NaN` do not. */
const NUMBER_TEXT = /^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$/;

/**
 * Reads what was typed into a limit field, by the bounds the route sent for it. The server answers for the
 * same three things at its own 422, and still has the last word; this only keeps a value that can never be
 * sent as an integer (a blank, a decimal, a word) from going out as a number.
 */
export function parseLimit(text: string, bound: { min: number; max: number }): LimitParse {
  const trimmed = text.trim();
  if (trimmed === "") return { ok: false, reason: "empty" };
  const value = NUMBER_TEXT.test(trimmed) ? Number(trimmed) : Number.NaN;
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    return { ok: false, reason: "not_integer" };
  }
  if (value < bound.min || value > bound.max) {
    return { ok: false, reason: "out_of_range", min: bound.min, max: bound.max };
  }
  return { ok: true, value };
}

/**
 * The fields the admin edited, read against the effective limits: `changes` holds the ones whose integer
 * value differs (the PUT body), `errors` the ones that cannot be sent. A field that was not edited is in
 * neither. Each field is held to the bounds of the answer, never to a constant.
 */
export function limitChanges(
  limits: LimitsOut,
  edits: Readonly<Partial<Record<LimitField, string>>>,
): { changes: LimitsChange; errors: Partial<Record<LimitField, LimitFault>> } {
  const changes: LimitsChange = {};
  const errors: Partial<Record<LimitField, LimitFault>> = {};
  for (const name of LIMIT_FIELDS) {
    const text = edits[name];
    if (text === undefined) continue;
    const parsed = parseLimit(text, limits.bounds[name]);
    if (!parsed.ok) errors[name] = parsed;
    else if (parsed.value !== limits[name]) changes[name] = parsed.value;
  }
  return { changes, errors };
}
