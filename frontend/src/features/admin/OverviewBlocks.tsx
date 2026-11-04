// The parts of `/admin/overview` that only show what they are given (P11-T11, spec §4.1): the panel and the
// card, the error of a block that failed alone, the chart of the days, the funnel, the two small tables and
// the health list, and the skeleton of the page. They fetch nothing and write nothing; the page and the two
// blocks with a dialog (`FailedJobsBlock`, `InventoryBlock`) do that.
//
// Colours are the canvas's own: the tokens of `styles.css` where there is one, and the canvas's hex for the
// few it has no token for. They are classes, never a `style` attribute (the CSP forbids it), so the bars of the
// chart are SVG shapes whose size is an attribute.
import { useId, type ReactNode, type Ref } from "react";
import { Link } from "react-router";
import type { HealthCheck, OverviewResponse } from "../../api/admin";
import { DataTable, type Column } from "../../components/DataTable";
import { formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import {
  dayLabel,
  failedFirst,
  formatCount,
  funnelCounts,
  type DayPoint,
  type SectionFailure,
} from "./overviewModel";

const P = S.admin.overviewPage;

/** The look of a card and of a block: the canvas's #141A22 on #263241, 10 px corners. */
export const PANEL = "rounded-[10px] border border-border bg-surface px-5 py-[18px]";
/** A button drawn as an outline, for "Thử lại" and the close buttons. */
export const OUTLINE_BUTTON =
  "rounded-md border border-[#2e3a48] px-3 py-1.5 text-[13px] text-text hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";

/**
 * A block of the page: a section named by its heading, with an optional mark beside the heading.
 * `headingRef`: the block may send the focus to its heading (`tabIndex={-1}`: reachable by script, not by Tab),
 * when the control the admin used has left the page and the focus would fall to `<body>`.
 */
export function Panel({
  title,
  aside,
  className = "",
  headingRef,
  children,
}: {
  title: string;
  aside?: ReactNode;
  className?: string;
  headingRef?: Ref<HTMLHeadingElement>;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={`flex flex-col gap-3 ${PANEL} ${className}`}>
      <div className="flex items-center gap-2.5">
        <h2
          id={id}
          ref={headingRef}
          tabIndex={headingRef === undefined ? undefined : -1}
          className="grow text-[15px] font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text"
        >
          {title}
        </h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

/** A small mark beside a heading: a count, "8/10 ổn". `tone` is the canvas's green, amber or neutral. */
export function Mark({ tone, children }: { tone: "ok" | "warn"; children: ReactNode }) {
  const colours = tone === "ok" ? "bg-[#133528] text-[#9ff0c5]" : "bg-[#2a1a0a] text-[#fcd9a8]";
  return <span className={`rounded px-2 py-[3px] text-xs font-bold ${colours}`}>{children}</span>;
}

/** What a block shows when its own section failed: that it did, why, and a way to ask again. The rest of the page is unaffected. */
export function BlockError({ failure, onRetry }: { failure: SectionFailure; onRetry: () => void }) {
  return (
    <div
      role="alert"
      className="flex min-h-[120px] grow flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-[#3a4757] p-3 text-center text-[13.5px] text-[#c9d3df]"
    >
      <span>{P.blockFailed}</span>
      <span className="text-xs text-muted">{P.sectionError[failure]}</span>
      <button type="button" onClick={onRetry} className={OUTLINE_BUTTON}>
        {S.common.retry}
      </button>
    </div>
  );
}

/**
 * "Tri thức" (DEC-210, P13-T05): the learned-knowledge drafts that wait for an admin, and how many of them conflict
 * with an entry already approved, and the way to the page that reviews them (`/admin/knowledge`, P13-T06). Like the
 * other blocks it draws its own error, with a "Thử lại", when its section came back `null`.
 */
export function KnowledgeBlock({
  knowledge,
  failure,
  onRetry,
}: {
  /** `null` when the section failed. */
  knowledge: OverviewResponse["knowledge"];
  failure: SectionFailure | null;
  onRetry: () => void;
}) {
  const K = P.knowledge;
  return (
    <Panel title={K.title}>
      {failure !== null || knowledge === null ? (
        <BlockError failure={failure ?? "unknown"} onRetry={onRetry} />
      ) : (
        <div className="flex flex-col gap-3">
          <dl className="flex flex-col gap-2 text-[13px]">
            <div className="flex justify-between gap-2.5">
              <dt className="text-[#aeb9c6]">{K.pending}</dt>
              <dd>{formatCount(knowledge.pending)}</dd>
            </div>
            <div className="flex justify-between gap-2.5">
              <dt className="text-[#aeb9c6]">{K.conflicts}</dt>
              <dd>{formatCount(knowledge.conflicts)}</dd>
            </div>
          </dl>
          <Link
            to="/admin/knowledge"
            className="self-start text-[13px] underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text"
          >
            {K.open}
          </Link>
        </div>
      )}
    </Panel>
  );
}

// --- the four cards -----------------------------------------------------------------------------------------

/** A card of the row at the top. It is one `dl` item: the label, the number, and a line under it. */
export function Tile({ label, value, sub }: { label: string; value: ReactNode; sub: ReactNode }) {
  return (
    <div className={`flex flex-col gap-1.5 ${PANEL}`}>
      <dt className="text-[13px] text-muted">{label}</dt>
      <dd className="text-[30px] font-bold tracking-tight">{value}</dd>
      <dd className="text-[12.5px] text-[#aeb9c6]">{sub}</dd>
    </div>
  );
}

/** A card whose own section failed: a dash for the number, the reason, and a way to ask again. */
export function TileError({
  label,
  text,
  onRetry,
}: {
  label: string;
  text: string;
  onRetry: () => void;
}) {
  return (
    <Tile
      label={label}
      value={S.common.missing}
      sub={
        <span role="alert" className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[#fda4af]">
          <span>
            {P.tileFailed}. {text}
          </span>
          <button type="button" onClick={onRetry} className={OUTLINE_BUTTON}>
            {S.common.retry}
          </button>
        </span>
      }
    />
  );
}

// --- the chart ----------------------------------------------------------------------------------------------

const CHART = { width: 640, height: 240, axisY: 200, top: 30, side: 8, maxBar: 56 } as const;
/** Up to this many days every bar says its total; beyond it only the title of the bar does. */
const LABELLED_DAYS = 12;

/**
 * The days as stacked bars, the canvas's: the heads at the bottom in the strong blue, the duplicates they
 * absorbed above them in the pale one, the total over each bar. It is an SVG whose shapes carry their size as
 * attributes, with a title on each bar for the pointer and a table with the same numbers for a screen reader.
 */
export function DayChart({ days }: { days: readonly DayPoint[] }) {
  const biggest = Math.max(0, ...days.map((d) => d.total));
  const unit = biggest === 0 ? 0 : (CHART.axisY - CHART.top) / biggest;
  const slot = (CHART.width - 2 * CHART.side) / Math.max(1, days.length);
  const barWidth = Math.min(CHART.maxBar, slot * 0.6);
  // With many days, only every few-th label fits under its bar (31 days: every 4th).
  const every = days.length <= LABELLED_DAYS ? 1 : Math.ceil(days.length / 8);
  const size = (n: number) => Number((n * unit).toFixed(1));

  return (
    <div className="flex flex-col gap-3">
      <svg
        role="img"
        aria-label={P.byDay.chart}
        viewBox={`0 0 ${CHART.width} ${CHART.height}`}
        className="h-auto w-full"
      >
        <line x1={0} x2={CHART.width} y1={CHART.axisY} y2={CHART.axisY} className="stroke-border" />
        {days.map((d, i) => {
          const x = CHART.side + slot * i + (slot - barWidth) / 2;
          const heads = size(d.heads);
          const copies = size(d.duplicates);
          const center = CHART.side + slot * (i + 0.5);
          // Counted back from the last day, which is always labelled: today is the one the eye looks for.
          const showLabel = (days.length - 1 - i) % every === 0;
          return (
            <g key={d.day} data-day={d.day}>
              <title>
                {P.byDay.bar(
                  dayLabel(d.day),
                  formatCount(d.total),
                  formatCount(d.heads),
                  formatCount(d.duplicates),
                )}
              </title>
              <rect
                data-part="duplicates"
                x={x}
                y={CHART.axisY - heads - copies}
                width={barWidth}
                height={copies}
                rx={3}
                className="fill-[#2a3e5c]"
              />
              <rect
                data-part="heads"
                x={x}
                y={CHART.axisY - heads}
                width={barWidth}
                height={heads}
                className="fill-[#5b8def]"
              />
              {days.length <= LABELLED_DAYS && (
                <text
                  x={center}
                  y={CHART.axisY - heads - copies - 6}
                  textAnchor="middle"
                  className="fill-[#aeb9c6] text-[11.5px]"
                >
                  {formatCount(d.total)}
                </text>
              )}
              {showLabel && (
                <text
                  x={center}
                  y={CHART.axisY + 20}
                  textAnchor="middle"
                  className="fill-muted text-xs"
                >
                  {dayLabel(d.day)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <table className="sr-only">
        <caption>{P.byDay.title}</caption>
        <thead>
          <tr>
            <th scope="col">{P.byDay.day}</th>
            <th scope="col">{P.byDay.total}</th>
            <th scope="col">{P.byDay.heads}</th>
            <th scope="col">{P.byDay.duplicates}</th>
          </tr>
        </thead>
        <tbody>
          {days.map((d) => (
            <tr key={d.day}>
              <td>{dayLabel(d.day)}</td>
              <td>{formatCount(d.total)}</td>
              <td>{formatCount(d.heads)}</td>
              <td>{formatCount(d.duplicates)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// --- the funnel, the two small tables, the health list --------------------------------------------------------

/** "Tình trạng xử lý": the four status rows and ① coverage, each a number even when the API had none. */
export function FunnelList({ funnel }: { funnel: NonNullable<OverviewResponse["funnel"]> }) {
  const counts = funnelCounts(funnel);
  const rows: { key: string; label: string; value: string }[] = [
    ...counts.steps.map((step) => ({
      key: step.key,
      label: P.funnel[step.key],
      value: formatCount(step.count),
    })),
    // DEC-212: a row of its own, only while something is archived, between the statuses and ① coverage.
    ...(counts.archived > 0
      ? [{ key: "archived", label: P.funnel.archived, value: formatCount(counts.archived) }]
      : []),
    {
      key: "coverage",
      label: P.funnel.coverage,
      value: P.funnel.ofHeads(formatCount(counts.ready), formatCount(counts.heads)),
    },
  ];
  return (
    <dl className="flex flex-col gap-2.5 text-[13.5px]">
      {rows.map((row) => (
        <div key={row.key} className="flex justify-between gap-3">
          <dt className="text-[#aeb9c6]">{row.label}</dt>
          <dd className="font-semibold">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

type SourceRow = { key: string; label: string; alerts: number; heads: number | null };

const SOURCE_COLUMNS: Column<SourceRow>[] = [
  { id: "source", header: P.bySource.source, cell: (row) => row.label },
  {
    id: "alerts",
    header: P.bySource.alerts,
    className: "text-right",
    cell: (row) => formatCount(row.alerts),
  },
  {
    id: "heads",
    header: P.bySource.heads,
    className: "text-right",
    cell: (row) => (row.heads === null ? S.common.missing : formatCount(row.heads)),
  },
];

/** The sources, then what the intake refused, which has no heads. */
export function SourceTable({ by }: { by: NonNullable<OverviewResponse["by_source"]> }) {
  const rows: SourceRow[] = [
    ...by.rows.map((r) => ({
      key: `source:${r.source}`,
      label: r.source,
      alerts: r.alerts,
      heads: r.heads,
    })),
    { key: "rejected", label: P.bySource.rejected, alerts: by.rejected, heads: null },
  ];
  return (
    <DataTable
      label={P.bySource.title}
      columns={SOURCE_COLUMNS}
      rows={rows}
      rowKey={(row) => row.key}
    />
  );
}

type AgentRow = NonNullable<OverviewResponse["top_agents"]>[number];

const AGENT_COLUMNS: Column<AgentRow>[] = [
  {
    id: "agent",
    header: P.topAgents.agent,
    cell: (row) => <span className="font-mono text-xs">{row.agent_name}</span>,
  },
  {
    id: "alerts",
    header: P.topAgents.alerts,
    className: "text-right",
    cell: (row) => formatCount(row.alerts),
  },
];

export function AgentTable({ agents }: { agents: NonNullable<OverviewResponse["top_agents"]> }) {
  return (
    <DataTable
      label={P.topAgents.title}
      columns={AGENT_COLUMNS}
      rows={agents}
      rowKey={(row) => row.agent_name}
      empty={P.topAgents.empty}
    />
  );
}

/** The mark beside the health heading: how many checks are fine, green when all are and amber when one is not. */
export function HealthMark({ checks }: { checks: readonly HealthCheck[] }) {
  const ok = checks.filter((c) => c.ok).length;
  return (
    <Mark tone={ok === checks.length ? "ok" : "warn"}>{P.health.okOfTotal(ok, checks.length)}</Mark>
  );
}

/**
 * The checks of the newest health row, the failing ones first. A check is told by its Vietnamese label (its
 * name when this page has none; a failing one adds its name), and by the word "Lỗi" or "Ổn" for a screen
 * reader, not by colour alone; its detail is the server's own text.
 */
export function HealthList({
  checks,
  checkedAt,
}: {
  checks: readonly HealthCheck[];
  checkedAt: string;
}) {
  return (
    <>
      <dl className="flex flex-col gap-2 text-[13px]">
        {failedFirst(checks).map((check, i) => {
          const label = labelOf(P.health.check, check.name);
          return (
            <div key={`${i}:${check.name}`} className="flex justify-between gap-2.5">
              <dt className={check.ok ? "text-[#aeb9c6]" : "text-[#fda4af]"}>
                <span className="sr-only">{check.ok ? P.health.ok : P.health.failing}</span>
                {label}
                {/* A failing check also says its name, the one the audit log's health.alarm carries. */}
                {!check.ok && label !== check.name && (
                  <code className="ml-1.5 font-mono text-xs">{check.name}</code>
                )}
              </dt>
              <dd
                className={`min-w-0 break-words text-right font-mono text-[11.5px] ${check.ok ? "text-muted" : "text-[#fda4af]"}`}
              >
                {check.detail}
              </dd>
            </div>
          );
        })}
      </dl>
      <p className="text-[12.5px] text-muted">{P.health.checkedAt(formatTime(checkedAt))}</p>
    </>
  );
}

// --- loading ------------------------------------------------------------------------------------------------

function Bar({ className }: { className: string }) {
  return (
    <div data-skeleton aria-hidden="true" className={`rounded-md bg-[#1a222c] ${className}`} />
  );
}

/** The page while it is being read, in the layout of the page, so nothing jumps when the data arrives. */
export function OverviewSkeleton() {
  return (
    <div role="status" aria-busy="true" className="flex flex-col gap-5 motion-safe:animate-pulse">
      <span className="sr-only">{S.common.loading}</span>
      <div className="grid grid-cols-4 gap-4" aria-hidden="true">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} data-skeleton className={`flex flex-col gap-2 ${PANEL}`}>
            <Bar className="h-3.5 w-1/2" />
            <Bar className="h-8 w-2/3" />
            <Bar className="h-3 w-3/4" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-4" aria-hidden="true">
        <div className={`col-span-2 ${PANEL}`}>
          <Bar className="h-60" />
        </div>
        <div className={`flex flex-col gap-3 ${PANEL}`}>
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <Bar key={i} className="h-3.5" />
          ))}
        </div>
      </div>
      <div className="grid grid-cols-3 gap-4" aria-hidden="true">
        {[0, 1, 2].map((i) => (
          <div key={i} className={`flex flex-col gap-3 ${PANEL}`}>
            <Bar className="h-3.5 w-1/2" />
            <Bar className="h-3.5" />
            <Bar className="h-3.5 w-4/5" />
            <Bar className="h-3.5 w-3/5" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-3 gap-4" aria-hidden="true">
        <div className={`col-span-2 flex flex-col gap-3 ${PANEL}`}>
          <Bar className="h-3.5 w-1/4" />
          <Bar className="h-3.5" />
          <Bar className="h-3.5" />
          <Bar className="h-3.5" />
        </div>
        <div className={`flex flex-col gap-3 ${PANEL}`}>
          <Bar className="h-3.5 w-1/2" />
          <Bar className="h-3.5" />
          <Bar className="h-3.5" />
        </div>
      </div>
    </div>
  );
}
