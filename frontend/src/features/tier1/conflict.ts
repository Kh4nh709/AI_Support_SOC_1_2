// What a failed decision says, in words. The 409 of a decision carries a flat body (`ConflictBody`, from
// decide.DecisionConflict.body); the words are `S.decision.conflict`'s. A kind this
// UI does not know is worded as "not actionable any more": the page refetches the alert either way, so what
// it then shows is the truth, and the sentence only has to say that the decision did not go through.
import { ApiError } from "../../api/client";
import type { ConflictBody } from "../../api/tier1";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";

const C = S.decision.conflict;

const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null;

/** The body of a 409, wherever the API wrapper left it. */
function conflictBodyOf(error: ApiError): Partial<ConflictBody> {
  if (isRecord(error.detail)) return error.detail as Partial<ConflictBody>;
  return isRecord(error.body) ? (error.body as Partial<ConflictBody>) : {};
}

/** The count of the cluster a `cluster_grew` answer reports, or null for a 409 of another kind. */
export function grownCountOf(error: ApiError): number | null {
  const body = conflictBodyOf(error);
  return body.kind === "cluster_grew" && typeof body.occurrence_count === "number"
    ? body.occurrence_count
    : null;
}

export function conflictText(error: ApiError): string {
  const body = conflictBodyOf(error);
  switch (body.kind) {
    case "cluster_grew": {
      const { seen_occurrence_count: seen, occurrence_count: now, delta, tolerance } = body;
      if (
        typeof seen !== "number" ||
        typeof now !== "number" ||
        typeof delta !== "number" ||
        typeof tolerance !== "number"
      ) {
        return S.common.unknownError;
      }
      return C.clusterGrew(seen, now, delta, tolerance);
    }
    case "already_decided":
      return C.alreadyDecided(
        body.decided_by ?? C.system,
        labelOf(S.status, body.decision ?? body.status),
        formatDateTime(body.decided_at),
      );
    case "already_in_case":
      return C.alreadyInCase;
    case "not_reopenable":
      return C.notReopenable;
    default:
      return C.notActive;
  }
}

/** The message of a 422 for the field it is about: the server's own text, or a plain "not valid". */
export function invalidText(error: ApiError): string {
  return typeof error.detail === "string" && error.detail !== ""
    ? error.detail
    : S.decision.invalid;
}
