// The KPI cards and the two charts, from one read of `GET /api/ti/stats?days=30`. The stats do not follow the list's filters: they are the
// page's overview. A busy or failed read says so in the place of both, and the table below carries on.
import { useQuery } from "@tanstack/react-query";
import { TI_DAYS, fetchTiStats, type TiStats } from "../../api/ti";
import { S } from "../../strings";
import { DayChart } from "./DayChart";
import { KpiCards } from "./KpiCards";
import { MalwareChart } from "./MalwareChart";
import { SectionError } from "./Notices";
import { TI_POLL_MS, tiKeys, useTiRetry } from "./tiQueries";

const CARD = "flex min-w-0 flex-col gap-2 rounded border border-border bg-surface p-3";

export function StatsSection() {
  const retry = useTiRetry();
  const query = useQuery<TiStats>({
    queryKey: tiKeys.stats(TI_DAYS),
    queryFn: ({ signal }) => fetchTiStats(TI_DAYS, signal),
    refetchInterval: TI_POLL_MS,
    retry,
  });
  const stats = query.data;
  if (stats === undefined) {
    return query.isError ? (
      <SectionError
        error={query.error}
        message={S.ti.loadError.stats}
        onRetry={() => void query.refetch()}
      />
    ) : (
      <p role="status" className="text-sm text-muted">
        {S.common.loading}
      </p>
    );
  }
  return (
    <>
      <KpiCards stats={stats} />
      <section aria-label={S.ti.charts.label} className="grid gap-4 lg:grid-cols-2">
        <div className={CARD}>
          <h2 className="text-sm font-semibold">{S.ti.charts.perDay.title(stats.days)}</h2>
          <DayChart days={stats.by_day} sources={stats.sources} />
        </div>
        <div className={CARD}>
          <h2 className="text-sm font-semibold">{S.ti.charts.topMalware.title}</h2>
          <MalwareChart items={stats.top_malware} />
        </div>
      </section>
    </>
  );
}
