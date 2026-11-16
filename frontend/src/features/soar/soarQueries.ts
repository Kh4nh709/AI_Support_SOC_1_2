// The cache keys and the polling of the SOAR page, in one place: the header's badge and the page both read the count,
// and a decision patches the rows of every list under `["soar", "list"]`. There is no WebSocket for the SOAR tickets:
// the list asks again every 20 s, the count every 30 s.
import { fetchSoarCount } from "../../api/soar";

export const SOAR_LIST_POLL_MS = 20_000;
export const SOAR_COUNT_POLL_MS = 30_000;

export const soarKeys = {
  all: ["soar"] as const,
  lists: ["soar", "list"] as const,
  list: (tab: string, q: string, page: number) => ["soar", "list", tab, q, page] as const,
  count: ["soar", "count"] as const,
  notices: ["soar", "notices"] as const,
  detail: (id: string) => ["soar", "detail", id] as const,
};

/**
 * The count of open tickets the header shows and watches. It keeps asking while the tab is in the background
 * (`refetchIntervalInBackground`): a new ticket is the one thing worth a tone when the analyst is looking at another
 * tab, and TanStack's default would stop the clock exactly then.
 */
export function countQueryOptions() {
  return {
    queryKey: soarKeys.count,
    queryFn: ({ signal }: { signal: AbortSignal }) => fetchSoarCount(signal),
    refetchInterval: SOAR_COUNT_POLL_MS,
    refetchIntervalInBackground: true,
  };
}
