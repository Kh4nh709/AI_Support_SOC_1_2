// A latch around a TanStack mutation, so a write is never sent twice by two clicks of one button.
//
//   const create = useMutation({ mutationFn: createUser, ... });
//   const run = useSubmitLatch(create);
//   <button onClick={() => run(body)}>
//
// Why `disabled={mutation.isPending}` is not enough: TanStack Query 5 tells React that a mutation went pending
// through a `setTimeout(0)`, so a second click that lands in the same tick (a double click of an automated
// browser, two events before React has rendered) still sees the enabled button and its `isPending === false`,
// and calls `mutate` again: two POSTs, two users. The latch is a REF, set before the call and cleared when
// the call settles, so the second call returns at once whatever React has rendered.
//
// `run(variables, options?)` returns `true` when it sent the call and `false` when it turned it away (the
// options of a call turned away are never used). The caller's own `onSettled` is chained: the latch is
// released first, then it runs, so it may send again. The mutation's own `onSuccess`/`onError`/`onSettled` of
// `useMutation({...})` are untouched.
//
// The latch is released by the REQUEST'S OWN promise (`mutateAsync`), and by `onSettled` too, which is
// the same moment seen from the call's options. It does not watch the mutation's status: `reset()` takes the
// observer off a call that is out, so TanStack drops that call's own `onSettled`, and the mutation's status
// goes back to idle while the request is still on its way (a latch opened by "idle" would allow a second write
// in flight), or never changes at all when `reset()` lands in the tick of `run()` (React never renders pending,
// and a latch that waits for idle stays shut for good). Each call holds a token, so a late settle of an
// abandoned call cannot free a newer one.
import type { MutateOptions, UseMutationResult } from "@tanstack/react-query";
import { useCallback, useRef } from "react";

export function useSubmitLatch<TData, TError, TVariables, TContext>(
  mutation: UseMutationResult<TData, TError, TVariables, TContext>,
): (
  variables: TVariables,
  options?: MutateOptions<TData, TError, TVariables, TContext>,
) => boolean {
  const out = useRef<object | null>(null);
  const { mutateAsync } = mutation;

  return useCallback(
    (variables, options) => {
      if (out.current !== null) return false;
      const token = {};
      out.current = token;
      const release = () => {
        if (out.current === token) out.current = null;
      };
      mutateAsync(variables, {
        ...options,
        onSettled: (...settled) => {
          release();
          options?.onSettled?.(...settled);
        },
      })
        .catch(() => undefined)
        .finally(release);
      return true;
    },
    [mutateAsync],
  );
}
