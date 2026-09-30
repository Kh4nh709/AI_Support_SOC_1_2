// src/features/tier2/useLoad.test.tsx — the one rule that keeps a page honest when it reads something else:
// only the newest read counts, so an answer that arrives late for what the page no longer shows is dropped.
import { act, renderHook, waitFor } from "@testing-library/react";
import { useLoad } from "./useLoad";

function deferred<T>() {
  let resolve: (value: T) => void = () => {};
  let reject: (reason: unknown) => void = () => {};
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("useLoad, the newest read", () => {
  it("drops the answer of a fetcher that was replaced while it was still pending", async () => {
    const first = deferred<string>();
    const fetchFirst = () => first.promise;
    const fetchSecond = () => Promise.resolve("second");
    const { result, rerender } = renderHook(({ fetcher }) => useLoad(fetcher), {
      initialProps: { fetcher: fetchFirst },
    });
    rerender({ fetcher: fetchSecond });
    await waitFor(() => expect(result.current.data).toBe("second"));

    await act(async () => {
      first.resolve("first");
      await first.promise;
    });
    expect(result.current.data).toBe("second");
    expect(result.current.loading).toBe(false);
  });

  it("drops the failure of a fetcher that was replaced while it was still pending", async () => {
    const first = deferred<string>();
    const fetchFirst = () => first.promise;
    const fetchSecond = () => Promise.resolve("second");
    const { result, rerender } = renderHook(({ fetcher }) => useLoad(fetcher), {
      initialProps: { fetcher: fetchFirst },
    });
    rerender({ fetcher: fetchSecond });
    await waitFor(() => expect(result.current.data).toBe("second"));

    await act(async () => {
      first.reject(new Error("boom"));
      await first.promise.catch(() => undefined);
    });
    expect(result.current.data).toBe("second");
    expect(result.current.error).toBeNull();
  });

  it("keeps the newer of two reads of one fetcher when the older answers last", async () => {
    const older = deferred<string>();
    const newer = deferred<string>();
    const answers = [older, newer];
    let calls = 0;
    const fetcher = () => {
      const next = answers[calls] ?? newer;
      calls += 1;
      return next.promise;
    };
    const { result } = renderHook(() => useLoad(fetcher));
    // The read on mount is the older one, the reload the newer.
    await waitFor(() => expect(calls).toBe(1));
    act(() => {
      void result.current.reload();
    });
    await waitFor(() => expect(calls).toBe(2));

    await act(async () => {
      newer.resolve("newer");
      await newer.promise;
    });
    await act(async () => {
      older.resolve("older");
      await older.promise;
    });
    expect(result.current.data).toBe("newer");
  });

  it("drops a read still in flight when the caller hands it an answer of its own", async () => {
    const pending = deferred<string>();
    const fetcher = () => pending.promise;
    const { result } = renderHook(() => useLoad(fetcher));
    act(() => result.current.replace("posted"));
    expect(result.current.data).toBe("posted");

    await act(async () => {
      pending.resolve("read before the post");
      await pending.promise;
    });
    expect(result.current.data).toBe("posted");
  });
});
