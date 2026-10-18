// `/admin/overview` (P11-T11, spec §4.1): the admin's first screen, the canvas's `AdminOverview`. One read,
// `GET /api/admin/overview?range=`, feeds nine sections, and each fails alone: a section that came back
// `null` draws its own error (AdminStates, "một khối lỗi") while the others show. The fourth card, the LLM
// cost of the month against its cap, is not in that answer: it is `GET /api/admin/llm/usage?range=month`
// (the same read the LLM page shows), so it has its own loading and its own error too.
//
// TanStack Query owns both reads and refetches them every 60 seconds while the tab is visible (spec §3). The two
// writes, the retry of a failed job and the reload of the inventory, live in `FailedJobsBlock` and
// `InventoryBlock`, each with its dialog; this file composes the page and tells its states apart:
//   - loading: a skeleton in the layout of the page;
//   - the read failed: the page's error with a retry, and the range select, so another range can be tried;
//   - a refresh failed while an earlier answer is on screen: that answer stays, with a note saying so;
//   - a range with no alert: the cards say 0, the chart is empty, and a card says why.
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { useId, useState } from "react";
import {
  ADMIN_RANGES,
  adminErrorOf,
  getLlmUsage,
  getOverview,
  type AdminRange,
  type LlmUsage,
  type OverviewResponse,
} from "../../api/admin";
import { PageError } from "../../components/PageError";
import { formatTime } from "../../format";
import { S } from "../../strings";
import { adminKeys } from "./adminKeys";
import { FailedJobsBlock } from "./FailedJobsBlock";
import { InventoryBlock } from "./InventoryBlock";
import {
  AgentTable,
  BlockError,
  DayChart,
  FunnelList,
  HealthList,
  HealthMark,
  OUTLINE_BUTTON,
  OverviewSkeleton,
  PANEL,
  Panel,
  SourceTable,
  Tile,
  TileError,
  TileLoading,
} from "./OverviewBlocks";
import {
  formatCap,
  formatCount,
  formatPct,
  formatSpend,
  sectionFailure,
  zeroFillDays,
  type SectionFailure,
} from "./overviewModel";

const P = S.admin.overviewPage;

/** Both reads are asked again this often, while the tab is visible (spec §3). */
const REFRESH_MS = 60_000;

const isoOf = (ms: number): string => new Date(ms).toISOString();

export function OverviewPage() {
  const [range, setRange] = useState<AdminRange>("24h");
  const rangeId = useId();
  const overview = useQuery({
    queryKey: adminKeys.overview(range),
    queryFn: () => getOverview(range),
    refetchInterval: REFRESH_MS,
  });
  const usage = useQuery({
    queryKey: adminKeys.llmUsage("month"),
    queryFn: () => getLlmUsage("month"),
    refetchInterval: REFRESH_MS,
  });
  const data = overview.data;
  const unreadable = data === undefined && overview.isError;
  const readAgain = () => void overview.refetch();

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end gap-4">
        <div className="flex grow flex-col gap-1">
          {/* The error of the page has the h1 of its own: there is one h1 in every state. */}
          {!unreadable && <h1 className="text-[26px] font-semibold">{S.admin.title.overview}</h1>}
          {data !== undefined && (
            <span className="text-sm text-[#aeb9c6]">
              {P.updated(formatTime(isoOf(overview.dataUpdatedAt)))}
            </span>
          )}
        </div>
        <div className="flex flex-col gap-[5px]">
          <label htmlFor={rangeId} className="text-xs text-muted">
            {P.rangeLabel}
          </label>
          <select
            id={rangeId}
            value={range}
            onChange={(event) => {
              const picked = ADMIN_RANGES.find((r) => r === event.target.value);
              if (picked !== undefined) setRange(picked);
            }}
            className="h-10 w-[170px] rounded-md border border-[#2e3a48] bg-[#0f141b] px-2.5 text-sm text-text focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text"
          >
            {ADMIN_RANGES.map((r) => (
              <option key={r} value={r}>
                {S.admin.range[r]}
              </option>
            ))}
          </select>
        </div>
      </div>

      {data === undefined ? (
        unreadable ? (
          <PageError title={S.admin.common.loadError} onRetry={readAgain} />
        ) : (
          <OverviewSkeleton />
        )
      ) : (
        <>
          {overview.isRefetchError && (
            <div
              role="alert"
              className="flex items-center gap-3 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-2.5 text-[13.5px] text-[#fcd9a8]"
            >
              <span className="grow">
                {P.refreshFailed(formatTime(isoOf(overview.dataUpdatedAt)))}
              </span>
              <button type="button" onClick={readAgain} className={OUTLINE_BUTTON}>
                {S.common.retry}
              </button>
            </div>
          )}
          <OverviewBody
            data={data}
            range={range}
            nowMs={overview.dataUpdatedAt}
            usage={usage}
            onRetryRead={readAgain}
          />
        </>
      )}
    </div>
  );
}

function OverviewBody({
  data,
  range,
  nowMs,
  usage,
  onRetryRead,
}: {
  data: OverviewResponse;
  range: AdminRange;
  /** When the answer arrived: the clock the days of the range are counted back from. */
  nowMs: number;
  usage: UseQueryResult<LlmUsage>;
  onRetryRead: () => void;
}) {
  const failure = (section: Parameters<typeof sectionFailure>[1]): SectionFailure =>
    sectionFailure(data, section) ?? "unknown";
  const block = (section: Parameters<typeof sectionFailure>[1]) => (
    <BlockError failure={failure(section)} onRetry={onRetryRead} />
  );
  const tileError = (section: Parameters<typeof sectionFailure>[1], label: string) => (
    <TileError label={label} text={P.sectionError[failure(section)]} onRetry={onRetryRead} />
  );

  const days = data.alerts_by_day === null ? null : zeroFillDays(data.alerts_by_day, range, nowMs);
  const received = days?.reduce((sum, d) => sum + d.total, 0) ?? 0;
  const heads = days?.reduce((sum, d) => sum + d.heads, 0) ?? 0;
  // Only a day series that arrived can say the range is empty: one that failed says nothing.
  const emptyRange = days !== null && received === 0;
  const health = data.health;

  return (
    <>
      <dl className="grid grid-cols-4 gap-4">
        {days === null ? (
          tileError("alerts_by_day", P.kpi.received)
        ) : (
          <Tile
            label={P.kpi.received}
            value={formatCount(received)}
            sub={P.kpi.receivedSub(S.admin.range[range], formatCount(heads))}
          />
        )}
        {data.waiting === null ? (
          tileError("waiting", P.kpi.waiting)
        ) : (
          <Tile
            label={P.kpi.waiting}
            value={formatCount(data.waiting.count)}
            sub={
              data.waiting.oldest_received_at === null
                ? P.kpi.waitingNone
                : P.kpi.waitingOldest(formatTime(data.waiting.oldest_received_at))
            }
          />
        )}
        {data.cases_open === null ? (
          tileError("cases_open", P.kpi.casesOpen)
        ) : (
          <Tile
            label={P.kpi.casesOpen}
            value={formatCount(data.cases_open)}
            sub={P.kpi.casesOpenSub}
          />
        )}
        <LlmTile usage={usage} />
      </dl>

      {emptyRange && (
        <div className={`flex flex-col gap-2 ${PANEL}`}>
          <h2 className="text-[17px] font-semibold">{P.emptyRange(S.admin.range[range])}</h2>
          <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{P.emptyRangeHint}</p>
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        <Panel
          title={P.byDay.title}
          className="col-span-2"
          aside={<span className="text-xs text-muted">{P.byDay.legend}</span>}
        >
          {days === null ? block("alerts_by_day") : <DayChart days={days} />}
        </Panel>
        <Panel title={P.funnel.title}>
          {data.funnel === null ? block("funnel") : <FunnelList funnel={data.funnel} />}
        </Panel>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Panel title={P.bySource.title}>
          {data.by_source === null ? block("by_source") : <SourceTable by={data.by_source} />}
        </Panel>
        <Panel title={P.topAgents.title}>
          {data.top_agents === null ? block("top_agents") : <AgentTable agents={data.top_agents} />}
        </Panel>
        <Panel
          title={P.health.title}
          aside={
            health !== null && health.checks.length > 0 ? (
              <HealthMark checks={health.checks} />
            ) : undefined
          }
        >
          {sectionFailure(data, "health") !== null ? (
            block("health")
          ) : health === null || health.checks.length === 0 ? (
            // No check has run yet: not an error, so no retry.
            <p className="text-[13px] text-muted">{P.health.none}</p>
          ) : (
            <HealthList checks={health.checks} checkedAt={health.checked_at} />
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <FailedJobsBlock
          jobs={data.failed_jobs}
          failure={sectionFailure(data, "failed_jobs")}
          onRetryRead={onRetryRead}
        />
        <InventoryBlock
          inventory={data.inventory}
          failure={sectionFailure(data, "inventory")}
          onRetryRead={onRetryRead}
        />
      </div>
    </>
  );
}

/** The fourth card: the month's LLM cost against the cap. It is read apart from the overview, so it waits and fails apart. */
function LlmTile({ usage }: { usage: UseQueryResult<LlmUsage> }) {
  if (usage.data !== undefined) {
    const { spent_usd, cap_usd, pct } = usage.data.month;
    return (
      <Tile
        label={P.kpi.llmCost}
        value={formatSpend(spent_usd)}
        sub={
          cap_usd === null || pct === null
            ? P.kpi.llmCapUnknown
            : P.kpi.llmCap(formatCap(cap_usd), formatPct(pct))
        }
      />
    );
  }
  if (usage.isError) {
    const error = adminErrorOf(usage.error);
    const text =
      error.kind === "reason" && (error.reason === "timeout" || error.reason === "query_failed")
        ? P.sectionError[error.reason]
        : S.common.unknownError;
    return <TileError label={P.kpi.llmCost} text={text} onRetry={() => void usage.refetch()} />;
  }
  return <TileLoading label={P.kpi.llmCost} />;
}
