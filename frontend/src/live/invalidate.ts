// What a live change does to the cache, and how often. A pull of 500 alerts is a storm of messages (the
// server already coalesces it, P10-T05); this is the client's half of Review Focus 2: the queue is fetched
// again about once per burst, never once per alert.
//
// The rule is a leading-and-trailing throttle with a 500 ms window:
//   - a change with no window open flushes at once, and opens a window;
//   - the changes that come while it is open are folded together and flushed once when it closes, which
//     opens the next window;
//   - a window that closes with nothing waiting just ends.
// So a burst costs two flushes (the first change, and the rest of it), and a steady stream at most one
// per 500 ms. A flush never aborts a fetch that is under way: see `refresh`.
import type { QueryClient } from "@tanstack/react-query";
import type { LiveChange } from "./socket";

export const INVALIDATE_MS = 500;

export type Invalidator = {
  push(change: LiveChange): void;
  /** Drops what is waiting and ignores every later change (the provider is going away). */
  cancel(): void;
};

/** What is waiting: the ids of the window, or "many" (which covers every id). */
type Waiting = Set<string> | "many";

export function createInvalidator(client: QueryClient, windowMs = INVALIDATE_MS): Invalidator {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let waiting: Waiting | null = null;
  let cancelled = false;

  // Only the queries that are on screen refetch; the others are marked stale and refetch when opened.
  //
  // A fetch that is already under way is NOT aborted (`cancelRefetch: false`). Aborting it, TanStack's
  // default, starves the list: with an answer slower than the window, a steady stream would abort each fetch
  // before it landed, and nothing would show until the stream stopped. But the fetch under way started
  // before this change, so it may not carry it: once it has landed, the query is fetched once more. That is
  // the trailing fetch of the throttle, and it is never concurrent with the one it follows.
  const refresh = (queryKey: readonly unknown[]) => {
    const busy = client.isFetching({ queryKey }) > 0;
    const settled = client.invalidateQueries({ queryKey }, { cancelRefetch: false });
    if (!busy) return;
    void settled.then(() => {
      if (!cancelled) void client.invalidateQueries({ queryKey }, { cancelRefetch: false });
    });
  };

  const flush = (change: Waiting) => {
    refresh(["queue"]);
    if (change === "many") {
      refresh(["alert"]);
    } else {
      for (const id of change) refresh(["alert", id]);
    }
  };

  const openWindow = () => {
    timer = setTimeout(() => {
      timer = undefined;
      if (waiting === null) return;
      const change = waiting;
      waiting = null;
      flush(change);
      openWindow();
    }, windowMs);
  };

  return {
    push(change) {
      if (cancelled) return;
      const incoming: Waiting = change === "many" ? "many" : new Set(change);
      if (timer === undefined) {
        flush(incoming);
        openWindow();
      } else if (waiting === "many" || incoming === "many") {
        waiting = "many";
      } else {
        waiting = new Set([...(waiting ?? []), ...incoming]);
      }
    },
    cancel() {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      waiting = null;
    },
  };
}
