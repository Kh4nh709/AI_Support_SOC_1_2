// src/live/invalidate.test.ts — Review Focus 2: a burst of changes is one refetch of the queue, not one
// per alert. The rule: the first change flushes at once, the ones that follow within 500 ms are folded
// into one flush at the end of that window, and a window opens after every flush.
import { QueryClient } from "@tanstack/react-query";
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
