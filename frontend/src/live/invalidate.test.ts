// src/live/invalidate.test.ts — Review Focus 2: a burst of changes is one refetch of the queue, not one
// per alert. The rule: the first change flushes at once, the ones that follow within 500 ms are folded
// into one flush at the end of that window, and a window opens after every flush.
import { QueryClient, QueryObserver } from "@tanstack/react-query";
import type { MockInstance } from "vitest";
import { INVALIDATE_MS, createInvalidator } from "./invalidate";

let client: QueryClient;
let spy: MockInstance<QueryClient["invalidateQueries"]>;
beforeEach(() => {
  vi.useFakeTimers();
  client = new QueryClient();
  spy = vi.spyOn(client, "invalidateQueries");
});
afterEach(() => {
  vi.useRealTimers();
});

/** The keys invalidated so far, as text, oldest first. */
const keys = (): string[] => spy.mock.calls.map((call) => JSON.stringify(call[0]?.queryKey));
const queueFlushes = () => keys().filter((k) => k === '["queue"]').length;

describe("createInvalidator", () => {
  it("flushes the first change at once: the queue and the alert it names", () => {
    const inv = createInvalidator(client);
    inv.push(["a1"]);
    expect(keys()).toEqual(['["queue"]', '["alert","a1"]']);
  });

  it("gives a burst of 50 changes inside 100 ms two queue flushes at most, one now and one at the end of the window", () => {
    const inv = createInvalidator(client);
    for (let i = 0; i < 50; i++) {
      inv.push([`a${i}`]);
      vi.advanceTimersByTime(2);
    }
    expect(queueFlushes()).toBe(1); // the leading one
    vi.advanceTimersByTime(INVALIDATE_MS);
    expect(queueFlushes()).toBe(2); // the trailing one
    vi.advanceTimersByTime(INVALIDATE_MS * 10);
    expect(queueFlushes()).toBe(2); // and nothing after
  });

  it("carries every id of the window into its closing flush", () => {
    const inv = createInvalidator(client);
    inv.push(["a1"]);
    inv.push(["a2", "a3"]);
    inv.push(["a2"]);
    vi.advanceTimersByTime(INVALIDATE_MS);
    expect(keys()).toEqual([
      '["queue"]',
      '["alert","a1"]',
      '["queue"]',
      '["alert","a2"]',
      '["alert","a3"]',
    ]);
  });

  it("does not flush a second time when nothing came in during the window", () => {
    const inv = createInvalidator(client);
    inv.push(["a1"]);
    vi.advanceTimersByTime(INVALIDATE_MS * 4);
    expect(queueFlushes()).toBe(1);
  });

  it("flushes at once again when the window has passed quietly", () => {
    const inv = createInvalidator(client);
    inv.push(["a1"]);
    vi.advanceTimersByTime(INVALIDATE_MS + 1);
    inv.push(["a2"]);
    expect(queueFlushes()).toBe(2);
  });

  it("never flushes the queue more than once in any 500 ms of a steady stream", () => {
    const inv = createInvalidator(client);
    const at: number[] = [];
    spy.mockImplementation((filters) => {
      if (JSON.stringify(filters?.queryKey) === '["queue"]') {
        at.push(Date.now());
      }
      return Promise.resolve();
    });
    for (let i = 0; i < 100; i++) {
      inv.push([`a${i}`]);
      vi.advanceTimersByTime(50); // 5 s of changes, 20 a second
    }
    vi.advanceTimersByTime(INVALIDATE_MS);
    expect(at.length).toBeGreaterThan(2);
    for (let i = 1; i < at.length; i++) {
      expect((at[i] ?? 0) - (at[i - 1] ?? 0)).toBeGreaterThanOrEqual(INVALIDATE_MS);
    }
  });

  it("invalidates every alert when the server says 'many', and that wins over ids in the same window", () => {
    const inv = createInvalidator(client);
    inv.push("many");
    expect(keys()).toEqual(['["queue"]', '["alert"]']);
    inv.push(["a1"]);
    inv.push("many");
    inv.push(["a2"]);
    vi.advanceTimersByTime(INVALIDATE_MS);
    expect(keys().slice(2)).toEqual(['["queue"]', '["alert"]']);
  });

  it("drops a waiting flush and everything after it once cancelled", () => {
    const inv = createInvalidator(client);
    inv.push(["a1"]);
    inv.push(["a2"]);
    inv.cancel();
    vi.advanceTimersByTime(INVALIDATE_MS * 4);
    inv.push(["a3"]);
    expect(queueFlushes()).toBe(1);
  });
});

// A flush must not starve the list: if it aborted the fetch under way, a steady stream (a flush every 500 ms)
// with an answer slower than 500 ms would never see one land. The fetch under way is let alone, and a change
// that came after it started is fetched once more when it has landed.
describe("with a fetch under way", () => {
  const SLOW_MS = INVALIDATE_MS + 200;

  /** A queue query on screen whose fetch takes `ms`. `data()` is the number of the last fetch that landed. */
  function queueOnScreen(ms: number) {
    const log = { started: 0, aborted: [] as number[] };
    const observer = new QueryObserver(client, {
      queryKey: ["queue"],
      queryFn: ({ signal }) => {
        const n = ++log.started;
        signal.addEventListener("abort", () => log.aborted.push(n));
        return new Promise<number>((resolve) => setTimeout(() => resolve(n), ms));
      },
    });
    const stop = observer.subscribe(() => {});
    return { log, data: () => observer.getCurrentResult().data, stop };
  }

  it("lets a slow fetch land while a steady stream keeps flushing, and aborts none", async () => {
    const queue = queueOnScreen(SLOW_MS);
    await vi.advanceTimersByTimeAsync(SLOW_MS); // the first fetch has landed: there is data to keep
    expect(queue.data()).toBe(1);
    const inv = createInvalidator(client);
    let newest = 0;
    for (let i = 0; i < 30; i++) {
      inv.push([`a${i}`]); // 3 s of changes, 10 a second
      await vi.advanceTimersByTimeAsync(100);
      newest = Math.max(newest, queue.data() ?? 0);
    }
    expect(newest).toBeGreaterThan(1); // the list moved while the stream was still on
    expect(queue.log.aborted).toEqual([]);
    inv.cancel();
    queue.stop();
  });

  it("fetches once more when it has landed if a change came after it started", async () => {
    const queue = queueOnScreen(SLOW_MS);
    await vi.advanceTimersByTimeAsync(SLOW_MS);
    const inv = createInvalidator(client);
    inv.push(["a1"]); // the second fetch starts now and lands at SLOW_MS
    expect(queue.log.started).toBe(2);
    await vi.advanceTimersByTimeAsync(100);
    inv.push(["a2"]); // a change the second fetch may not have seen: its flush comes at INVALIDATE_MS
    await vi.advanceTimersByTimeAsync(SLOW_MS - 100 + 1); // the second has landed
    expect(queue.data()).toBe(2);
    expect(queue.log.started).toBe(3); // and the third is on its way
    await vi.advanceTimersByTimeAsync(SLOW_MS);
    expect(queue.data()).toBe(3);
    expect(queue.log.aborted).toEqual([]);
    await vi.advanceTimersByTimeAsync(INVALIDATE_MS * 4);
    expect(queue.log.started).toBe(3); // and no fourth: nothing came in since
    inv.cancel();
    queue.stop();
  });

  it("does not fetch again after it has landed when the change came before it started", async () => {
    const queue = queueOnScreen(SLOW_MS);
    await vi.advanceTimersByTimeAsync(SLOW_MS);
    const inv = createInvalidator(client);
    inv.push(["a1"]);
    await vi.advanceTimersByTimeAsync(SLOW_MS * 4);
    expect(queue.log.started).toBe(2);
    inv.cancel();
    queue.stop();
  });

  it("does not fetch again after cancel", async () => {
    const queue = queueOnScreen(SLOW_MS);
    await vi.advanceTimersByTimeAsync(SLOW_MS);
    const inv = createInvalidator(client);
    inv.push(["a1"]);
    await vi.advanceTimersByTimeAsync(100);
    inv.push(["a2"]);
    await vi.advanceTimersByTimeAsync(INVALIDATE_MS); // its flush joins the fetch under way
    inv.cancel();
    await vi.advanceTimersByTimeAsync(SLOW_MS * 4);
    expect(queue.log.started).toBe(2);
    queue.stop();
  });
});
