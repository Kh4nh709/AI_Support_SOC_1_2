// The cache keys and the polling of the Threat Intel page. The data changes once a day (the host's cron imports at 07:00), so nothing here
// asks often: the status and the stats ask again every five minutes (so the stale banner appears while a page is left open), the list
// only when the view changes or the window is focused again (a table that moves under the analyst's hand is worse than a late row).
import type { TiView } from "./tiParams";

export const TI_POLL_MS = 300_000;

export const tiKeys = {
  all: ["ti"] as const,
  status: ["ti", "status"] as const,
  stats: (days: number) => ["ti", "stats", days] as const,
  list: (view: TiView) => ["ti", "list", view] as const,
};
