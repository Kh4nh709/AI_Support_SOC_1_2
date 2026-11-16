// What a decision says on its row, in words: the lines for each answer of the decision route (spec section 4, step 6), and
// for each way the route itself can refuse (local 403, 404, 409, 503) or fail (the network). A message n8n sent is shown
// as it came; the fixed sentences are `strings.ts`'s. Nothing here decides anything: it only words what happened.
import { ApiError } from "../../api/client";
import type { SoarDecisionAnswer, SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { statusText } from "./model";

/** One line under a row's buttons: an error (said at once to a screen reader) or a note (said politely). */
export type RowLine = { tone: "error" | "note"; text: string };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

/** A review as the API serves it: at least an id and a status, which is all a row needs to be drawn from. */
export function isReview(value: unknown): value is SoarReview {
  return isRecord(value) && typeof value.id === "string" && typeof value.status === "string";
}

const message = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

/** The lines of an answer the route gave (n8n was asked): by `outcome`. */
export function answerLines(answer: SoarDecisionAnswer): RowLine[] {
  const said = message(answer.message);
  const status = isReview(answer.review) ? statusText(answer.review) : S.common.missing;
  const lines: RowLine[] = [];
  switch (answer.outcome) {
    case "ok":
      lines.push({ tone: "note", text: S.soar.result.ok(status) });
      if (said !== null) lines.push({ tone: "note", text: said });
      break;
    case "failed":
      lines.push({ tone: "error", text: said ?? S.soar.result.failedNoMessage });
      break;
    case "unavailable":
      lines.push({ tone: "error", text: said ?? S.soar.result.unavailableNoMessage });
      break;
    case "conflict":
      lines.push({ tone: "note", text: S.soar.result.conflict(status) });
      if (said !== null) lines.push({ tone: "note", text: said });
      break;
    default:
      lines.push({ tone: "error", text: S.common.unknownError });
  }
  return lines;
}

/** What a refusal or a failure of the call itself says, and the row it carried (a local 409 carries it), if any. */
export function failureOf(error: unknown): {
  lines: RowLine[];
  review: SoarReview | null;
  /** The list should be read again: the page does not know what the row is now. */
  refetch: boolean;
} {
  if (!(error instanceof ApiError)) {
    return {
      lines: [{ tone: "error", text: S.soar.result.network }],
      review: null,
      refetch: false,
    };
  }
  const line = (tone: RowLine["tone"], text: string): RowLine[] => [{ tone, text }];
  switch (error.status) {
    case 403:
      return { lines: line("error", S.soar.result.forbidden), review: null, refetch: false };
    case 503:
      return { lines: line("error", S.soar.result.notConfigured), review: null, refetch: false };
    case 404:
      return { lines: line("error", S.soar.result.notFound), review: null, refetch: true };
    case 409: {
      const detail = isRecord(error.detail) ? error.detail : {};
      const text = detail.reason === "locked" ? S.soar.result.locked : S.soar.result.invalidState;
      const review = isReview(detail.review) ? detail.review : null;
      return { lines: line("note", text), review, refetch: review === null };
    }
    default:
      return { lines: line("error", S.common.unknownError), review: null, refetch: false };
  }
}
