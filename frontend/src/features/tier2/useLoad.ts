// One read of the backend for a page: the last good answer, the last failure, and a way to read again.
// A read made again (after a note, say) keeps showing the last answer until the new one arrives, so a
// form the reader is typing in is never torn down. A page that reads something else (another offset)
// passes a different `fetcher`; until that read answers, `loading` is true and `data` is the old answer.
import { useCallback, useEffect, useRef, useState } from "react";

type State<T> = { data: T | null; error: unknown; source: unknown };

export type Load<T> = {
  /** The last good answer, or null before the first one. */
  data: T | null;
  /** The failure of the read `fetcher` made, or null once it answers. */
  error: unknown;
  /** True until the read `fetcher` makes has answered, well or badly. */
  loading: boolean;
  /** Reads again with the same `fetcher`; resolves to the answer, or null on a failure. */
  reload: () => Promise<T | null>;
  /** Takes an answer the caller already has (the body of a POST) and drops any read still in flight. */
  replace: (data: T) => void;
};

export function useLoad<T>(fetcher: () => Promise<T>): Load<T> {
  const [state, setState] = useState<State<T>>({ data: null, error: null, source: null });
  // Only the newest read counts: an older answer that arrives late is dropped.
  const latest = useRef(0);

  const reload = useCallback(async (): Promise<T | null> => {
    latest.current += 1;
    const mine = latest.current;
    try {
      const data = await fetcher();
      if (latest.current === mine) setState({ data, error: null, source: fetcher });
      return data;
    } catch (error) {
      if (latest.current === mine)
        setState((last) => ({ data: last.data, error, source: fetcher }));
      return null;
    }
  }, [fetcher]);

  const replace = useCallback(
    (data: T): void => {
      latest.current += 1;
      setState({ data, error: null, source: fetcher });
    },
    [fetcher],
  );

  useEffect(() => {
    void reload();
  }, [reload]);

  const answered = state.source === fetcher;
  return {
    data: state.data,
    error: answered ? state.error : null,
    loading: !answered,
    reload,
    replace,
  };
}
