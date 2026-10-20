// `/admin/llm` (spec §4.3, P11-T13): what the model costs and how it is limited.
//
// One read, `GET /api/admin/llm/usage?range=`, refetched every 60 seconds, owns the whole page: the four
// tiles, the table by pipeline and role, the ② quota of the last 24 hours, the last 20 calls and the limits
// block. The limits block is the one part the route lets fail alone (`limits: null` with `limits_error`): the
// rest is still shown, and the block becomes the read-only fail-closed panel (`LlmLimits.tsx`).
//
// Three rules the numbers follow:
//   - the red "stopped" state is `spent_usd >= cap_usd` and never `pct` (the route floors `pct`), and amber
//     is `pct >= 80` below the cap (`costState`, llmFigures.ts);
//   - the month is the calendar month whatever the range says, begins at the midnight of the database
//     session's time zone, and `projected_usd` is the route's own (floored at one day), shown as it came;
//   - the quota is the last 24 hours, never a calendar day.
// A bar is a `<progress>` and no element has a `style` attribute: the CSP forbids one.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useId, useState, type ReactNode } from "react";
import { Link } from "react-router";
import {
  LLM_RANGES,
  adminErrorOf,
  getLlmUsage,
  type LlmRange,
  type LlmUsage,
  type PipelineRoleRow,
  type RecentRun,
} from "../../api/admin";
import { DataTable, type Column } from "../../components/DataTable";
import { PageError } from "../../components/PageError";
import { Toast } from "../../components/Toast";
import { formatTime } from "../../format";
import { S, adminReasonText, labelOf } from "../../strings";
import { adminKeys } from "./adminKeys";
import { LlmLimits } from "./LlmLimits";
import {
  costState,
  formatCount,
  formatLatency,
  formatPercent,
  formatSeconds,
  formatTokens,
  formatUsd,
  pipelineLabel,
  pipelineMark,
  shortId,
  stoppedEntries,
  subjectLink,
  summarise,
  type CostState,
} from "./llmFigures";

const L = S.admin.llmPage;

/** The page is read again this often while the tab is open. */
const REFRESH_MS = 60_000;

/** The month first (the canvas's), then the three rolling ranges. */
const RANGE_ORDER: readonly LlmRange[] = ["month", ...LLM_RANGES.filter((r) => r !== "month")];

const PANEL = "flex flex-col gap-3 rounded-[10px] border border-border bg-surface px-5 py-[18px]";
const MUTED = "text-[#aeb9c6]";
const AMBER = "text-[#fcd9a8]";
const NUMBER = "text-right tabular-nums";

// --- the tiles ----------------------------------------------------------------------------------------------

const TILE_BORDER: Record<CostState, string> = {
  ok: "border-border",
  warn: "border-[#5a3a14]",
  stopped: "border-[#5a2e36]",
};
const VALUE_TONE: Record<CostState, string> = {
  ok: "",
  warn: AMBER,
  stopped: "text-[#fda4af]",
};
// Whole class names: Tailwind finds a class by reading the source. The two pseudo-elements are how a
// `<progress>` is painted (WebKit and Firefox), since an inline style cannot be.
const BAR_BASE =
  "h-2 w-full appearance-none overflow-hidden rounded bg-[#1f2833] [&::-webkit-progress-bar]:bg-[#1f2833]";
const BAR_TONE: Record<CostState, string> = {
  ok: "[&::-webkit-progress-value]:bg-[#5b8def] [&::-moz-progress-bar]:bg-[#5b8def]",
  warn: "[&::-webkit-progress-value]:bg-[#f59e0b] [&::-moz-progress-bar]:bg-[#f59e0b]",
  stopped: "[&::-webkit-progress-value]:bg-[#f87171] [&::-moz-progress-bar]:bg-[#f87171]",
};

function Tile({
  title,
  children,
  border = "border-border",
  state,
}: {
  title: string;
  children: ReactNode;
  border?: string;
  state?: CostState;
}) {
  const id = useId();
  return (
    <section
      aria-labelledby={id}
      data-cost={state}
      className={`flex flex-col gap-2 rounded-[10px] border bg-surface px-5 py-[18px] ${border}`}
    >
      <h2 id={id} className="text-[13px] font-normal text-muted">
        {title}
      </h2>
      {children}
    </section>
  );
}

/** The big figure of a tile, and the smaller one beside it ("$24,60 / $30"). */
function Figure({ value, of, tone = "" }: { value: string; of?: string; tone?: string }) {
  return (
    <p className="text-2xl font-bold break-words">
      <span className={tone}>{value}</span>
      {of !== undefined && (
        <>
          {" "}
          <span className={`text-[15px] font-medium ${MUTED}`}>{of}</span>
        </>
      )}
    </p>
  );
}

function CostTile({ month }: { month: LlmUsage["month"] }) {
  const state = costState(month);
  const { spent_usd: spent, cap_usd: cap } = month;
  return (
    <Tile title={L.cost.title} border={TILE_BORDER[state]} state={state}>
      <Figure
        value={formatUsd(spent)}
        of={`/ ${cap === null ? S.common.missing : formatUsd(cap, true)}`}
        tone={VALUE_TONE[state]}
      />
      {cap !== null && (
        <progress
          aria-label={L.cost.barLabel}
          value={Math.min(spent, cap)}
          max={cap}
          className={`${BAR_BASE} ${BAR_TONE[state]}`}
        />
      )}
      {state === "stopped" && (
        <div
          role="alert"
          className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3 py-2.5 text-[13px] leading-snug text-[#fda4af]"
        >
          {L.cost.stopped}
        </div>
      )}
      {state === "warn" && (
        <p className={`text-[12.5px] ${AMBER}`}>{L.cost.warn(formatPercent(month.pct ?? 0))}</p>
      )}
      {cap === null ? (
        <p className={`text-[12.5px] ${MUTED}`}>{L.cost.noCap}</p>
      ) : (
        state !== "stopped" && (
          <p className={`text-[12.5px] ${MUTED}`}>
            {L.cost.left(formatUsd(cap - spent))} ·{" "}
            {L.cost.projected(formatUsd(month.projected_usd))}
          </p>
        )
      )}
      <p className="text-xs leading-snug text-muted">{L.cost.monthNote}</p>
    </Tile>
  );
}

function Tiles({ data }: { data: LlmUsage }) {
  const sum = summarise(data.by_pipeline_role);
  const averages = sum.byPipeline
    .filter((p) => p.calls > 0)
    .map((p) =>
      L.tokens.averageOf(
        pipelineMark(p.pipeline),
        formatCount(Math.round(p.inputTokens / p.calls)),
      ),
    );
  // Over `runs`, not `calls`: a ① verifier failure is written on both of its rows (summarise).
  const stoppedPct = sum.runs === 0 ? null : Math.round((sum.stopped / sum.runs) * 1000) / 10;
  return (
    <div className="grid grid-cols-4 gap-4">
      <CostTile month={data.month} />
      <Tile title={L.calls.title}>
        <Figure value={formatCount(sum.calls)} />
        <p className={`text-[12.5px] ${MUTED}`}>
          {sum.byPipeline.length === 0
            ? S.common.missing
            : sum.byPipeline
                .map((p) => `${pipelineMark(p.pipeline)} ${formatCount(p.calls)}`)
                .join(" · ")}
        </p>
      </Tile>
      <Tile title={L.tokens.title}>
        <Figure value={formatTokens(sum.inputTokens)} of={`/ ${formatTokens(sum.outputTokens)}`} />
        <p className={`text-[12.5px] ${MUTED}`}>
          {averages.length === 0 ? S.common.missing : L.tokens.average(averages.join(" · "))}
        </p>
      </Tile>
      <Tile title={L.stoppedTile.title}>
        <Figure
          value={stoppedPct === null ? S.common.missing : formatPercent(stoppedPct)}
          tone={sum.stopped > 0 ? AMBER : ""}
        />
        <p className={`text-[12.5px] ${MUTED}`}>
          {sum.mainStopped === null
            ? L.stoppedTile.none
            : L.stoppedTile.detail(
                formatCount(sum.stopped),
                formatCount(sum.runs),
                labelOf(L.stopped, sum.mainStopped.code),
              )}
        </p>
      </Tile>
    </div>
  );
}

// --- by pipeline and role -------------------------------------------------------------------------------------

function StoppedCell({ stopped }: { stopped: Readonly<Record<string, number>> }) {
  const entries = stoppedEntries(stopped);
  if (entries.length === 0) return <span className={MUTED}>{S.common.missing}</span>;
  return (
    <span className={AMBER}>
      {entries.map(([code, count]) => `${labelOf(L.stopped, code)} ${count}`).join(" · ")}
    </span>
  );
}

const PIPELINE_COLUMNS: Column<PipelineRoleRow>[] = [
  {
    id: "pipeline",
    header: L.byPipeline.colPipeline,
    cell: (row) => pipelineLabel(row.pipeline, row.role),
  },
  {
    id: "calls",
    header: L.byPipeline.colCalls,
    cell: (row) => formatCount(row.calls),
    className: NUMBER,
  },
  {
    id: "with_result",
    header: L.byPipeline.colWithResult,
    cell: (row) => formatCount(row.with_result),
    className: NUMBER,
  },
  {
    id: "stopped",
    header: L.byPipeline.colStopped,
    cell: (row) => <StoppedCell stopped={row.stopped} />,
  },
  {
    id: "latency",
    header: L.byPipeline.colLatency,
    cell: (row) => formatLatency(row.latency_p50_ms, row.latency_p95_ms),
    className: NUMBER,
  },
  {
    id: "cost",
    header: L.byPipeline.colCost,
    cell: (row) => formatUsd(row.cost_usd),
    className: NUMBER,
  },
];

function ByPipeline({ data }: { data: LlmUsage }) {
  const id = useId();
  const rows = data.by_pipeline_role;
  return (
    <section aria-labelledby={id} className={`${PANEL} col-span-2`}>
      <h2 id={id} className="text-[15px] font-semibold">
        {L.byPipeline.title}
      </h2>
      {rows.length === 0 ? (
        <div className="space-y-2 py-2">
          <h3 className="text-[17px] font-semibold">
            {L.noCalls.title(S.admin.range[data.range].toLowerCase())}
          </h3>
          <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{L.noCalls.body}</p>
        </div>
      ) : (
        <DataTable
          label={L.byPipeline.label}
          columns={PIPELINE_COLUMNS}
          rows={rows}
          rowKey={(row) => `${row.pipeline}/${row.role ?? ""}`}
        />
      )}
      <p className="text-xs leading-relaxed text-muted">
        {L.byPipeline.toolCalls(data.tool_calls)}
      </p>
    </section>
  );
}

// --- the quota of ② ---------------------------------------------------------------------------------------------

type QuotaUser = LlmUsage["quota"]["users"][number];

const QUOTA_COLUMNS: Column<QuotaUser>[] = [
  {
    id: "user",
    header: L.quota.colUser,
    cell: (user) => (
      <>
        <span className="font-mono">{user.username}</span>
        {user.display_name !== null &&
          user.display_name !== "" &&
          user.display_name !== user.username && (
            <span className="block text-xs text-muted">{user.display_name}</span>
          )}
      </>
    ),
  },
  {
    id: "used",
    header: L.quota.colUsed,
    cell: (user) => formatCount(user.used),
    className: NUMBER,
  },
  {
    id: "left",
    header: L.quota.colLeft,
    cell: (user) =>
      user.remaining === null ? (
        S.common.missing
      ) : user.remaining === 0 ? (
        <span className="font-semibold text-[#fda4af]">{L.quota.exhausted}</span>
      ) : (
        formatCount(user.remaining)
      ),
    className: NUMBER,
  },
];

function Quota({ quota }: { quota: LlmUsage["quota"] }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={PANEL}>
      <h2 id={id} className="text-[15px] font-semibold">
        {L.quota.title}
      </h2>
      <p className={`text-[12.5px] ${MUTED}`}>
        {quota.limit === null ? L.quota.limitUnknown : L.quota.limit(quota.limit)}
      </p>
      <DataTable
        label={L.quota.label}
        columns={QUOTA_COLUMNS}
        rows={quota.users}
        rowKey={(user) => user.username}
        empty={L.quota.empty}
      />
      <p className="text-xs leading-relaxed text-muted">{L.quota.note}</p>
    </section>
  );
}

// --- recent calls -----------------------------------------------------------------------------------------------

const LINK =
  "font-mono text-[#7fb0ff] underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-text";

/**
 * A run on an alert that is blind and not yet decided comes with no subject and no outcome (DEC-101, context pack
 * §6.4): the one case in which an alert's run has no id. Both cells say it is withheld rather than missing.
 */
const isWithheld = (run: RecentRun): boolean =>
  run.subject_type === "alert" && (run.subject_id === null || run.subject_id === "");

function Subject({ run }: { run: RecentRun }) {
  const id = run.subject_id;
  if (isWithheld(run)) return <span className={MUTED}>{L.recent.hidden}</span>;
  if (id === null || id === "") return <span className={MUTED}>{S.common.missing}</span>;
  const short = shortId(id);
  const text = run.subject_type === null ? short : L.recent.subject(run.subject_type, short);
  const to = subjectLink(run.subject_type, id);
  return to === null ? (
    <span className="font-mono" title={id}>
      {text}
    </span>
  ) : (
    <Link to={to} title={id} className={LINK}>
      {text}
    </Link>
  );
}

/**
 * The verdict of a run. ① proposer: `suggested_action`; ② : `suggested_conclusion`; ① verifier: its own
 * `structured_only_verdict` (from the facts and the decision table alone), said as that and never as an
 * agreement with the proposer. A run with no verdict is `stopped:<stopped_by>`.
 */
function Outcome({ run }: { run: RecentRun }) {
  const outcome = run.outcome;
  if (isWithheld(run) && (outcome === null || outcome === "")) {
    return <span className={MUTED}>{L.recent.hidden}</span>;
  }
  if (outcome === null || outcome === "") return <span className={MUTED}>{S.common.missing}</span>;
  if (outcome.startsWith("stopped:")) {
    return (
      <span className={AMBER}>
        {L.recent.stopped(labelOf(L.stopped, outcome.slice("stopped:".length)))}
      </span>
    );
  }
  const verdict = labelOf(
    run.pipeline === "investigate" ? S.ai2.suggestedConclusion : S.ai1.action,
    outcome,
  );
  const verifier = run.pipeline === "triage" && run.role === "verifier";
  return <span>{verifier ? L.recent.verifier(verdict) : verdict}</span>;
}

const count = (value: number | null) => (value === null ? S.common.missing : formatCount(value));

const RECENT_COLUMNS: Column<RecentRun>[] = [
  {
    id: "at",
    header: L.recent.colAt,
    cell: (run) => <span className={MUTED}>{formatTime(run.created_at)}</span>,
  },
  {
    id: "pipeline",
    header: L.recent.colPipeline,
    cell: (run) => pipelineLabel(run.pipeline, run.role),
  },
  { id: "subject", header: L.recent.colSubject, cell: (run) => <Subject run={run} /> },
  {
    id: "tokens",
    header: L.recent.colTokens,
    cell: (run) => `${count(run.input_tokens)} / ${count(run.output_tokens)}`,
    className: NUMBER,
  },
  {
    id: "latency",
    header: L.recent.colLatency,
    cell: (run) => formatSeconds(run.latency_ms),
    className: NUMBER,
  },
  { id: "outcome", header: L.recent.colOutcome, cell: (run) => <Outcome run={run} /> },
  {
    id: "cost",
    header: L.recent.colCost,
    cell: (run) => (run.cost_usd === null ? S.common.missing : formatUsd(run.cost_usd)),
    className: NUMBER,
  },
];

function Recent({ runs }: { runs: readonly RecentRun[] }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={`${PANEL} col-span-2`}>
      <div className="flex items-baseline gap-2.5">
        <h2 id={id} className="text-[15px] font-semibold">
          {L.recent.title}
        </h2>
        <span className="text-xs text-muted">{L.recent.note}</span>
      </div>
      <DataTable
        label={L.recent.label}
        columns={RECENT_COLUMNS}
        rows={runs}
        rowKey={(run) => run.run_id}
        empty={L.recent.empty}
      />
    </section>
  );
}

// --- loading and failing -----------------------------------------------------------------------------------------

const SKELETON = "animate-pulse rounded-lg bg-[#1a222c]";

/** The page's own title and the layout's blocks, so nothing jumps when the data arrives. */
function Skeleton() {
  return (
    <div className="space-y-5">
      <h1 className="text-2xl font-semibold">{S.admin.title.llm}</h1>
      <div role="status" aria-busy="true" className="space-y-5">
        <span className="sr-only">{S.common.loading}</span>
        <div aria-hidden="true" className="grid grid-cols-4 gap-4">
          {[0, 1, 2, 3].map((n) => (
            <div key={n} className={`${SKELETON} h-32`} />
          ))}
        </div>
        <div aria-hidden="true" className="grid grid-cols-3 gap-4">
          <div className={`${SKELETON} col-span-2 h-64`} />
          <div className={`${SKELETON} h-64`} />
        </div>
        <div aria-hidden="true" className="grid grid-cols-3 gap-4">
          <div className={`${SKELETON} h-40`} />
          <div className={`${SKELETON} col-span-2 h-40`} />
        </div>
      </div>
    </div>
  );
}

/** What a failed first read says: the reason's own text for a 503 or a 403, else the status or the connection. */
function loadErrorHint(error: unknown): string {
  const failure = adminErrorOf(error);
  if (failure.kind === "reason" || failure.kind === "field") return adminReasonText(failure);
  return failure.status === 0 ? L.loadErrorOffline : L.loadErrorServer(failure.status);
}

// --- the page ---------------------------------------------------------------------------------------------------

export function LlmPage() {
  const [range, setRange] = useState<LlmRange>("month");
  const [saved, setSaved] = useState(false);
  const query = useQuery({
    queryKey: adminKeys.llmUsage(range),
    queryFn: () => getLlmUsage(range),
    refetchInterval: REFRESH_MS,
    // The page of the range just left stays on screen (and the form keeps what was typed) until the next
    // one answers.
    placeholderData: keepPreviousData,
  });
  const data = query.data;

  if (data === undefined) {
    if (query.isError) {
      return (
        <div className="space-y-3">
          <PageError title={S.admin.common.loadError} onRetry={() => void query.refetch()} />
          <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">
            {loadErrorHint(query.error)}
          </p>
        </div>
      );
    }
    return <Skeleton />;
  }

  // The limits are unreadable on either signal: the route sends both together, and neither alone may open the form.
  const failClosed = data.limits === null || data.limits_error !== null;

  return (
    <div className="space-y-5" aria-busy={query.isPlaceholderData}>
      <div className="flex items-end gap-4">
        <div className="flex-1 space-y-1">
          <h1 className="text-2xl font-semibold">{S.admin.title.llm}</h1>
          <p className={`text-sm ${MUTED}`}>{L.subtitle}</p>
        </div>
        <label className="flex flex-col gap-1.5 text-xs text-muted">
          {L.rangeLabel}
          <select
            value={range}
            onChange={(event) => setRange(event.target.value as LlmRange)}
            className="h-10 w-44 rounded-md border border-[#2e3a48] bg-[#0f141b] px-2.5 text-sm text-text focus-visible:outline-2 focus-visible:outline-text"
          >
            {RANGE_ORDER.map((name) => (
              <option key={name} value={name}>
                {S.admin.range[name]}
              </option>
            ))}
          </select>
        </label>
      </div>

      {saved && <Toast onClose={() => setSaved(false)}>{L.limits.saved}</Toast>}
      {query.isError && (
        <div
          role="alert"
          className="flex items-center justify-between gap-3 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-2.5 text-[13.5px] text-[#fcd9a8]"
        >
          <span>{L.refreshFailed}</span>
          <button
            type="button"
            onClick={() => void query.refetch()}
            className="rounded border border-[#5a3a14] px-2 py-0.5 text-xs hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
          >
            {S.common.retry}
          </button>
        </div>
      )}

      <Tiles data={data} />

      <div className="grid grid-cols-3 gap-4">
        <ByPipeline data={data} />
        <LlmLimits
          limits={data.limits}
          failClosed={failClosed}
          spentUsd={data.month.spent_usd}
          onSaved={() => setSaved(true)}
          onRefetch={() => void query.refetch()}
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Quota quota={data.quota} />
        <Recent runs={data.recent} />
      </div>
    </div>
  );
}
