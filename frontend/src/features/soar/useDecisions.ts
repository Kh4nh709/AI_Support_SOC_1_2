// The decisions of the page, one request at a time per ticket, and what each said, kept per ticket OUTSIDE the query
// cache: a refetch of the list replaces rows, and must not wipe "Đang xử lý…" or an error line, so the line is kept here
// and shown while the row is still the row it was about (`at` is the `updated_at` the answer left; when n8n changes the
// ticket the row's `updated_at` moves and the line goes). The answer's review is written into the cache at once, so the
// row shows what it now is; the count is asked again, and the ticket's detail.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useCallback, useRef, useState } from "react";
import {
  postSoarDecision,
  type SoarDecision,
  type SoarListResponse,
  type SoarReview,
  type SoarReviewDetail,
} from "../../api/soar";
import { cleanDeep, statusText } from "./model";
import { answerLines, failureOf, isReview, type RowLine } from "./outcome";
import { soarKeys } from "./soarQueries";
import { S } from "../../strings";

/** What a row was when a line was written about it: the lines are shown only while the row is still that. */
export type RowStamp = {
  updated_at: string | null;
  status: string;
  decided_at: string | null;
};

/**
 * The stamp of a row. `updated_at` moves on every write, but a line must not outlive a change of the status or of the
 * decision either (a later decision of someone else must never sit beside my failure), whatever the clock says.
 */
export const stampOf = (
  row: Pick<SoarReview, "updated_at" | "status" | "decided_at">,
): RowStamp => ({
  updated_at: row.updated_at ?? null,
  status: row.status,
  decided_at: row.decided_at ?? null,
});

export const sameStamp = (a: RowStamp, b: RowStamp): boolean =>
  a.updated_at === b.updated_at && a.status === b.status && a.decided_at === b.decided_at;

export type RowState = {
  /** The request is out (it may take up to 45 s). */
  running: boolean;
  lines: readonly RowLine[];
  /** The row the lines are about; they are shown only while the row still has this stamp. */
  at: RowStamp | null;
};

export type Decisions = {
  states: Readonly<Record<string, RowState>>;
  /** The note that stays after a decision went through, until it is closed. */
  toast: string | null;
  closeToast: () => void;
  /**
   * Where the focus should go: the row whose request has just started. Its button is disabled at that moment (and the dialog
   * it came from is gone), and a focused element that is disabled leaves the focus on the page; the row takes it instead.
   * A new object for each request, so the same row can ask again.
   */
  focus: { id: string } | null;
  /** The request has been used (the row has taken the focus): it must not be used again when the row is drawn anew. */
  clearFocus: () => void;
  run: (row: SoarReview, decision: SoarDecision, note: string) => Promise<void>;
};

/**
 * The list fetches to let go before an answer is written into the cache: those of lists that already HOLD rows, which a poll
 * on its way would overwrite with the old state of the ticket. A list that holds no data yet (a tab just opened) is
 * left alone: cancelling it would leave the rows of the previous tab on screen, dimmed, until the next poll.
 */
const OLD_POLLS = {
  queryKey: soarKeys.lists,
  predicate: (query: { state: { data: unknown } }) => query.state.data !== undefined,
};

export function useDecisions(): Decisions {
  const client = useQueryClient();
  const [states, setStates] = useState<Readonly<Record<string, RowState>>>({});
  const [toast, setToast] = useState<string | null>(null);
  const [focus, setFocus] = useState<{ id: string } | null>(null);
  // A second press can arrive before the first has been drawn as a disabled button: this says so at once.
  const out = useRef(new Set<string>());
  const mutation = useMutation({
    mutationFn: (call: { id: string; decision: SoarDecision; note: string }) =>
      postSoarDecision(
        call.id,
        call.note === ""
          ? { decision: call.decision }
          : { decision: call.decision, note: call.note },
      ).then((answer) => cleanDeep(answer)),
  });
  const { mutateAsync } = mutation;

  const put = useCallback((id: string, state: RowState) => {
    setStates((all) => ({ ...all, [id]: state }));
  }, []);

  /** Writes a review into every list the cache holds, and into the ticket's detail. */
  const write = useCallback(
    (review: SoarReview) => {
      client.setQueriesData<SoarListResponse>({ queryKey: soarKeys.lists }, (old) =>
        old === undefined
          ? old
          : { ...old, rows: old.rows.map((row) => (row.id === review.id ? review : row)) },
      );
      client.setQueryData<SoarReviewDetail>(soarKeys.detail(review.id), (old) =>
        old === undefined ? old : { ...old, ...review },
      );
    },
    [client],
  );

  const run = useCallback(
    async (row: SoarReview, decision: SoarDecision, note: string) => {
      if (out.current.has(row.id)) return;
      out.current.add(row.id);
      put(row.id, { running: true, lines: [], at: null });
      setFocus({ id: row.id });
      setToast(null);
      try {
        const answer = await mutateAsync({ id: row.id, decision, note });
        const review = isReview(answer.review) ? answer.review : null;
        // A poll that was already on its way saw the ticket before this answer: let it go, or it would land after the
        // answer and put the row back as it was (held, with the old buttons) until the next poll.
        await client.cancelQueries(OLD_POLLS);
        if (review !== null) write(review);
        put(row.id, {
          running: false,
          lines: answerLines(answer),
          at: stampOf(review ?? row),
        });
        if (answer.outcome === "ok" && review !== null) {
          setToast(S.soar.result.toast(row.id, statusText(review)));
        }
      } catch (error) {
        const failure = failureOf(error);
        if (failure.review !== null) {
          await client.cancelQueries(OLD_POLLS);
          write(failure.review);
        }
        put(row.id, {
          running: false,
          lines: failure.lines,
          at: stampOf(failure.review ?? row),
        });
        if (failure.refetch) void client.invalidateQueries({ queryKey: soarKeys.lists });
      } finally {
        out.current.delete(row.id);
        void client.invalidateQueries({ queryKey: soarKeys.count });
        void client.invalidateQueries({ queryKey: soarKeys.detail(row.id) });
      }
    },
    [client, mutateAsync, put, write],
  );

  const clearFocus = useCallback(() => setFocus(null), []);

  return { states, toast, closeToast: () => setToast(null), focus, clearFocus, run };
}
