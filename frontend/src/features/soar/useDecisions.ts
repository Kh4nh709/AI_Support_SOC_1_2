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
import { statusText } from "./model";
import { answerLines, failureOf, isReview, type RowLine } from "./outcome";
import { soarKeys } from "./soarQueries";
import { S } from "../../strings";

export type RowState = {
  /** The request is out (it may take up to 45 s). */
  running: boolean;
  lines: readonly RowLine[];
  /** The `updated_at` of the row the lines are about; they are shown only while the row still has it. */
  at: string | null;
};

export type Decisions = {
  states: Readonly<Record<string, RowState>>;
  /** The note that stays after a decision went through, until it is closed. */
  toast: string | null;
  closeToast: () => void;
  run: (row: SoarReview, decision: SoarDecision, note: string) => Promise<void>;
};

export function useDecisions(): Decisions {
  const client = useQueryClient();
  const [states, setStates] = useState<Readonly<Record<string, RowState>>>({});
  const [toast, setToast] = useState<string | null>(null);
  // A second press can arrive before the first has been drawn as a disabled button: this says so at once.
  const out = useRef(new Set<string>());
  const mutation = useMutation({
    mutationFn: (call: { id: string; decision: SoarDecision; note: string }) =>
      postSoarDecision(
        call.id,
        call.note === ""
          ? { decision: call.decision }
          : { decision: call.decision, note: call.note },
      ),
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
      setToast(null);
      try {
        const answer = await mutateAsync({ id: row.id, decision, note });
        const review = isReview(answer.review) ? answer.review : null;
        // A poll that was already on its way saw the ticket before this answer: let it go, or it would land after the
        // answer and put the row back as it was (held, with the old buttons) until the next poll.
        await client.cancelQueries({ queryKey: soarKeys.lists });
        if (review !== null) write(review);
        put(row.id, {
          running: false,
          lines: answerLines(answer),
          at: review?.updated_at ?? row.updated_at,
        });
        if (answer.outcome === "ok" && review !== null) {
          setToast(S.soar.result.toast(row.id, statusText(review)));
        }
      } catch (error) {
        const failure = failureOf(error);
        if (failure.review !== null) {
          await client.cancelQueries({ queryKey: soarKeys.lists });
          write(failure.review);
        }
        put(row.id, {
          running: false,
          lines: failure.lines,
          at: failure.review?.updated_at ?? row.updated_at,
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

  return { states, toast, closeToast: () => setToast(null), run };
}
