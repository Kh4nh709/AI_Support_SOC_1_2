// src/features/admin/useSubmitLatch.test.tsx — the latch that keeps a write from being sent twice (P11-T14 fix
// round 1). TanStack Query 5 tells React that a mutation is pending through a `setTimeout(0)`, so a button
// that is `disabled={mutation.isPending}` is still enabled for a second click that lands in the same tick.
// The latch is a ref, set before `mutate` and cleared when the call settles, so the second call returns at once.
import { QueryClient, QueryClientProvider, useMutation } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { useSubmitLatch } from "./useSubmitLatch";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** Lets every promise and `setTimeout(0)` that is ready run, so a settled call has released its latch. */
const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** A real mutation over `fn`, with the latch around it. */
function setup(fn: (vars: string) => Promise<string>) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return renderHook(
    () => {
      const mutation = useMutation({ mutationFn: fn });
      return { mutation, run: useSubmitLatch(mutation) };
    },
    { wrapper },
  );
}

describe("the gap the latch closes", () => {
  it("lets a plain mutate through twice when both calls land in one tick", async () => {
    const calls: string[] = [];
    const gate = deferred<string>();
    const { result } = setup((vars) => {
      calls.push(vars);
      return gate.promise;
    });
    await act(async () => {
      result.current.mutation.mutate("a");
      result.current.mutation.mutate("b");
    });
    expect(calls).toEqual(["a", "b"]);
    gate.resolve("done");
  });
});

describe("useSubmitLatch", () => {
  it("sends one mutate for two calls in the same tick, and says which one went", async () => {
    const calls: string[] = [];
    const gate = deferred<string>();
    const { result } = setup((vars) => {
      calls.push(vars);
      return gate.promise;
    });
    let went: boolean[] = [];
    await act(async () => {
      went = [result.current.run("a"), result.current.run("b"), result.current.run("c")];
    });
    expect(went).toEqual([true, false, false]);
    expect(calls).toEqual(["a"]);
    await act(async () => gate.resolve("done"));
    await waitFor(() => expect(result.current.mutation.isSuccess).toBe(true));
    expect(calls).toEqual(["a"]);
  });

  it("is released after a success", async () => {
    const calls: string[] = [];
    let gate = deferred<string>();
    const { result } = setup((vars) => {
      calls.push(vars);
      return gate.promise;
    });
    await act(async () => {
      result.current.run("a");
    });
    await act(async () => gate.resolve("one"));
    await waitFor(() => expect(result.current.mutation.isSuccess).toBe(true));
    gate = deferred<string>();
    let again = false;
    await act(async () => {
      again = result.current.run("b");
    });
    expect(again).toBe(true);
    expect(calls).toEqual(["a", "b"]);
    await act(async () => gate.resolve("two"));
  });

  it("is released after an error", async () => {
    const calls: string[] = [];
    let gate = deferred<string>();
    const { result } = setup((vars) => {
      calls.push(vars);
      return gate.promise;
    });
    await act(async () => {
      result.current.run("a");
    });
    await act(async () => gate.reject(new Error("boom")));
    await waitFor(() => expect(result.current.mutation.isError).toBe(true));
    gate = deferred<string>();
    let again = false;
    await act(async () => {
      again = result.current.run("b");
    });
    expect(again).toBe(true);
    expect(calls).toEqual(["a", "b"]);
    await act(async () => gate.resolve("two"));
  });

  it("stays shut after a reset while a call is out, until that call settles", async () => {
    // `reset()` takes the observer off the call, but the request is still on its way: a second write now
    // would be two in flight. The latch follows the request's own promise, not the mutation's state.
    const calls: string[] = [];
    const gates = [deferred<string>(), deferred<string>()];
    const { result } = setup((vars) => {
      calls.push(vars);
      return gates[calls.length - 1]!.promise;
    });
    await act(async () => {
      result.current.run("a");
    });
    await waitFor(() => expect(result.current.mutation.isPending).toBe(true));
    await act(async () => result.current.mutation.reset());
    await waitFor(() => expect(result.current.mutation.isIdle).toBe(true));
    let early = true;
    await act(async () => {
      early = result.current.run("b");
    });
    expect(early).toBe(false);
    expect(calls).toEqual(["a"]);
    await act(async () => gates[0]!.resolve("one"));
    await act(flush);
    let late = false;
    await act(async () => {
      late = result.current.run("c");
    });
    expect(late).toBe(true);
    expect(calls).toEqual(["a", "c"]);
    await act(async () => gates[1]!.resolve("two"));
  });

  it("is released when a call settles after a reset that came in the same tick as it", async () => {
    // `run` and `reset` before React renders anything: the pending state is never rendered, so nothing
    // that watches the mutation's status can see the call end, and TanStack drops the per-call `onSettled`.
    const calls: string[] = [];
    const gates = [deferred<string>(), deferred<string>()];
    const { result } = setup((vars) => {
      calls.push(vars);
      return gates[calls.length - 1]!.promise;
    });
    await act(async () => {
      result.current.run("a");
      result.current.mutation.reset();
    });
    let during = true;
    await act(async () => {
      during = result.current.run("b");
    });
    expect(during).toBe(false);
    await act(async () => gates[0]!.resolve("one"));
    await act(flush);
    let after = false;
    await act(async () => {
      after = result.current.run("c");
    });
    expect(after).toBe(true);
    expect(calls).toEqual(["a", "c"]);
    await act(async () => gates[1]!.resolve("two"));
  });

  it("is released when a call that was reset away fails", async () => {
    const calls: string[] = [];
    const gates = [deferred<string>(), deferred<string>()];
    const { result } = setup((vars) => {
      calls.push(vars);
      return gates[calls.length - 1]!.promise;
    });
    await act(async () => {
      result.current.run("a");
      result.current.mutation.reset();
    });
    await act(async () => gates[0]!.reject(new Error("boom")));
    await act(flush);
    let after = false;
    await act(async () => {
      after = result.current.run("b");
    });
    expect(after).toBe(true);
    await act(async () => gates[1]!.resolve("two"));
  });

  it("chains the caller's own onSettled, and calls it once with the answer", async () => {
    const gate = deferred<string>();
    const { result } = setup(() => gate.promise);
    const onSettled = vi.fn();
    await act(async () => {
      result.current.run("a", { onSettled });
    });
    expect(onSettled).not.toHaveBeenCalled();
    await act(async () => gate.resolve("answer"));
    await waitFor(() => expect(onSettled).toHaveBeenCalledTimes(1));
    expect(onSettled.mock.calls[0]?.slice(0, 3)).toEqual(["answer", null, "a"]);
  });

  it("chains the caller's own onSettled on an error too, and the other callbacks still run", async () => {
    const gate = deferred<string>();
    const { result } = setup(() => gate.promise);
    const onSettled = vi.fn();
    const onError = vi.fn();
    await act(async () => {
      result.current.run("a", { onSettled, onError });
    });
    const boom = new Error("boom");
    await act(async () => gate.reject(boom));
    await waitFor(() => expect(onSettled).toHaveBeenCalledTimes(1));
    expect(onError).toHaveBeenCalledTimes(1);
    expect(onSettled.mock.calls[0]?.slice(0, 3)).toEqual([undefined, boom, "a"]);
  });

  it("is released before the caller's onSettled runs, so the caller may send again from it", async () => {
    const calls: string[] = [];
    const gates = [deferred<string>(), deferred<string>()];
    const { result } = setup((vars) => {
      calls.push(vars);
      return gates[calls.length - 1]!.promise;
    });
    let again: boolean | null = null;
    await act(async () => {
      result.current.run("a", {
        onSettled: () => {
          again = result.current.run("b");
        },
      });
    });
    await act(async () => gates[0]!.resolve("one"));
    await waitFor(() => expect(again).not.toBeNull());
    expect(again).toBe(true);
    await waitFor(() => expect(calls).toEqual(["a", "b"]));
    // the first call's own promise settles after its onSettled: it must not free the call sent from it
    await act(flush);
    let third = true;
    await act(async () => {
      third = result.current.run("c");
    });
    expect(third).toBe(false);
    expect(calls).toEqual(["a", "b"]);
    await act(async () => gates[1]!.resolve("two"));
  });

  it("does not call the options of a call it turned away", async () => {
    const gate = deferred<string>();
    const { result } = setup(() => gate.promise);
    const turnedAway = vi.fn();
    await act(async () => {
      result.current.run("a");
      result.current.run("b", { onSettled: turnedAway, onSuccess: turnedAway });
    });
    await act(async () => gate.resolve("done"));
    await waitFor(() => expect(result.current.mutation.isSuccess).toBe(true));
    expect(turnedAway).not.toHaveBeenCalled();
  });
});
