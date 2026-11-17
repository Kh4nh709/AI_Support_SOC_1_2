// The cache keys and the polling of the Threat Intel page. The data changes once a day (the host's cron imports at 07:00), so nothing here
// asks often: the status and the stats ask again every five minutes (so the stale banner appears while a page is left open), the list
// only when the view changes or the window is focused again (a table that moves under the analyst's hand is worse than a late row).
import { useQueryClient } from "@tanstack/react-query";
import { isTiBusy } from "../../api/ti";
import type { TiView } from "./tiParams";

export const TI_POLL_MS = 300_000;

export const tiKeys = {
  all: ["ti"] as const,
  status: ["ti", "status"] as const,
  stats: (days: number) => ["ti", "stats", days] as const,
  list: (view: TiView) => ["ti", "list", view] as const,
};

/**
 * The `retry` of the page's three queries: a `503 {reason: timeout}` is not asked again (the statement already outlived the server's
 * limit, and asking twice more on a loaded database only adds to the load before "busy" shows; the section's own button asks when the
 * person wants), and everything else keeps what the client says (the app's rule: a 5xx twice, a refusal never).
 */
export function useTiRetry(): (failureCount: number, error: Error) => boolean {
  const client = useQueryClient();
  return (failureCount, error) => {
    if (isTiBusy(error)) return false;
    const base = client.getDefaultOptions().queries?.retry;
    if (typeof base === "function") return base(failureCount, error);
    if (typeof base === "number") return failureCount < base;
    return base ?? failureCount < 3;
  };
}
