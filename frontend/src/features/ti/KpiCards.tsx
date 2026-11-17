// The four cards (spec section 8, 2): new today (`imported_today`), confidence at or above 75 (`high_confidence`), the top three malware
// with their counts (the first three of `top_malware`, the Owner's words: NOT `newest_malware`, which stays served), and matched in logs
// (`matched_in_logs`, 0 until the matching is built). A malware name is text from a feed, printed through `shown`.
import { TI_HIGH_CONFIDENCE, type TiStats } from "../../api/ti";
import { S } from "../../strings";
import { shown } from "./display";

const CARD = "flex flex-col gap-1 rounded border border-border bg-surface px-3 py-2";
const LABEL = "text-xs text-muted";
const NUMBER = "text-2xl font-semibold tabular-nums";

/** How many malware the third card names. */
export const KPI_TOP = 3;

function Figure({ label, value }: { label: string; value: number }) {
  return (
    <div role="group" aria-label={label} className={CARD}>
      <p className={LABEL}>{label}</p>
      <p className={NUMBER}>{String(value)}</p>
    </div>
  );
}

export function KpiCards({ stats }: { stats: TiStats }) {
  const top = stats.top_malware.slice(0, KPI_TOP);
  return (
    <section aria-label={S.ti.kpi.label} className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Figure label={S.ti.kpi.today} value={stats.imported_today} />
      <Figure label={S.ti.kpi.high(TI_HIGH_CONFIDENCE)} value={stats.high_confidence} />
      <div role="group" aria-label={S.ti.kpi.top} className={CARD}>
        <p className={LABEL}>{S.ti.kpi.top}</p>
        {top.length === 0 ? (
          <p className="text-sm text-muted">{S.ti.kpi.topEmpty}</p>
        ) : (
          <ol className="flex flex-col gap-0.5 text-sm">
            {top.map((item, index) => (
              <li key={index} className="wrap-anywhere">
                {S.ti.kpi.topItem(shown(item.malware), item.count)}
              </li>
            ))}
          </ol>
        )}
      </div>
      <Figure label={S.ti.kpi.matched} value={stats.matched_in_logs} />
    </section>
  );
}
