// A latch around a TanStack mutation, so a write is never sent twice by two clicks of one button.
//
//   const create = useMutation({ mutationFn: createRule, ... });
//   const run = useSubmitLatch(create);
//   <button onClick={() => run(body)}>
//
// Why `disabled={mutation.isPending}` is not enough: TanStack Query 5 tells React that a mutation went pending
// through a `setTimeout(0)`, so a second click that lands in the same tick (a double click of an automated
// browser, two events before React has rendered) still sees the enabled button and its `isPending === false`,
// and calls `mutate` again: two POSTs, two rules. The latch is a REF, set before `mutate` and cleared when
// the call settles, so the second call returns at once whatever React has rendered.
//
// `run(variables, options?)` returns `true` when it sent the call and `false` when it turned it away (the
// options of a call turned away are never used). The caller's own `onSettled` is chained: the latch is
// released first, then it runs, so it may send again. The mutation's own `onSuccess`/`onError`/`onSettled` of
// `useMutation({...})` are untouched.
//
// Per-call callbacks of TanStack do not run when the mutation is reset while the call is out (`reset()` takes
// the observer off it), which would leave the latch shut for good; the latch is therefore also released
// whenever the mutation goes back to idle.
import type { MutateOptions, UseMutationResult } from "@tanstack/react-query";
import { useCallback, useEffect, useRef } from "react";

export function useSubmitLatch<TData, TError, TVariables, TContext>(
  mutation: UseMutationResult<TData, TError, TVariables, TContext>,
): (
  variables: TVariables,
  options?: MutateOptions<TData, TError, TVariables, TContext>,
) => boolean {
  const out = useRef(false);
  const { mutate, isIdle } = mutation;

  useEffect(() => {
    if (isIdle) out.current = false;
  }, [isIdle]);

  return useCallback(
    (variables, options) => {
      if (out.current) return false;
      out.current = true;
      mutate(variables, {
        ...options,
        onSettled: (...settled) => {
          out.current = false;
          options?.onSettled?.(...settled);
        },
      });
      return true;
    },
    [mutate],
  );
}
