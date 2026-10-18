// What a failed call of the rules page says, and where (spec §3, the AdminStates rules section).
//
// `adminErrorOf` (api/admin.ts) reads the server's `detail`. The rules routes answer in three shapes:
//   - a known reason (`"rule not found"` is `rule_not_found`, `"forbidden"` is `forbidden`): a text of
//     `S.admin.reason`, shown at the dialog or the form that made the call;
//   - a 422 about the CONDITIONS of a rule: the whitelist's own text (`"simulate: match is outside the
//     whitelist or malformed: ..."`, a plain string) or FastAPI's list-shaped detail (a condition that is not
//     an object, a `match` that is not an array: `[{type, loc, msg, input}]`). Both go at the conditions;
//   - anything else (a 5xx, the 503 of a server with auth off, a network failure): a sentence that says it
//     failed and that nothing was lost, from the caller.
import { adminErrorOf } from "../../api/admin";
import { ApiError } from "../../api/client";
import { S, adminReasonText } from "../../strings";

const R = S.admin.rulesPage.builder;

/** The words of a failure that is not about the conditions: a known reason's text, else `fallback`. */
export function failureText(error: unknown, fallback: string): string {
  const read = adminErrorOf(error);
  return read.kind === "reason" || read.kind === "field" ? adminReasonText(read) : fallback;
}

/** A 422 about the conditions: one sentence of ours, and what the server said (as text). */
export type ConditionProblem = { sentence: string; details: string[] };

/** The most lines of FastAPI's list that are shown: the rest says the same thing about the same body. */
const MAX_DETAILS = 5;

/** `loc: msg` for each entry of FastAPI's list that has a message. Anything else in the list is skipped. */
function listDetails(error: unknown): string[] {
  if (!(error instanceof ApiError) || !Array.isArray(error.detail)) return [];
  const lines: string[] = [];
  for (const item of error.detail as unknown[]) {
    if (typeof item !== "object" || item === null) continue;
    const { msg, loc } = item as { msg?: unknown; loc?: unknown };
    if (typeof msg !== "string" || msg === "") continue;
    const where = Array.isArray(loc)
      ? loc.filter((part) => typeof part === "string" || typeof part === "number").join(".")
      : "";
    lines.push(where === "" ? msg : `${where}: ${msg}`);
    if (lines.length === MAX_DETAILS) break;
  }
  return lines;
}

/**
 * The 422 of `simulate` and of the create, if that is what `error` is, else `null`. The whitelist's text, a
 * list of texts and FastAPI's list-shaped detail are all about the conditions: the form keeps what was typed
 * and the message goes under the conditions.
 */
export function conditionProblemOf(error: unknown): ConditionProblem | null {
  const read = adminErrorOf(error);
  if (read.status !== 422) return null;
  if (read.kind === "message") return { sentence: R.conditionRejected, details: [read.message] };
  if (read.kind === "messages") return { sentence: R.conditionRejected, details: read.messages };
  if (read.kind === "other") return { sentence: R.conditionMalformed, details: listDetails(error) };
  return null;
}
