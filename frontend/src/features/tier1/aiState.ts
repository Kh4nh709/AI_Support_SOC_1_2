// The one place the ① state is decided, for a queue row and for the alert view (P10-T09; the alert page,
// P10-T10, reuses it). The blind arm (DEC-101) is read from the response only: the server drops the ①
// keys from a blind, undecided head, and this file recognises that. It never fetches, infers or caches a
// suggestion any other way, so a component that wants to know "what does ① say" asks here and nowhere else.
import type { AlertView, QueueRow } from "../../api/tier1";

export type AiState =
  | { kind: "ready"; action: string; confidence: string | null; forced: boolean }
  | { kind: "hidden" }
  | { kind: "pending" }
  | { kind: "unavailable"; stoppedBy: string | null }
  | { kind: "decided"; action: string | null; confidence: string | null };

/** The statuses in which the server shows the ① verdict to everyone (visibility.SHOW_STATES). */
export const DECIDED: ReadonlySet<string> = new Set([
  "closed_fp",
  "closed_benign",
  "closed_confirmed",
  "escalated_tier2",
  "auto_closed",
]);

// Neither the queue nor the alert view says why ① gave up (`llm_runs.stopped_by` is not in either answer),
// so `unavailable` carries no reason from here; a caller that learns one may show it.
const UNAVAILABLE: AiState = { kind: "unavailable", stoppedBy: null };

/**
 * The state of the ① cell of a queue row.
 *  - No `suggested_action` KEY, `suggestion_visible === false`, and a status that is not decided: the blind
 *    arm, `hidden`. A blind row is never `pending`: "pending" would say ① is still working.
 *  - A string `suggested_action`: `ready`, forced when `gate_forced === true`.
 *  - `triage_status === "unavailable"`: `unavailable`.
 *  - Otherwise `pending`: the visible arm, no result yet.
 */
export function aiStateOfRow(row: QueueRow): AiState {
  if (!("suggested_action" in row) && row.suggestion_visible === false && !DECIDED.has(row.status)) {
    return { kind: "hidden" };
  }
  if (typeof row.suggested_action === "string") {
    return {
      kind: "ready",
      action: row.suggested_action,
      confidence: row.confidence ?? null,
      forced: row.gate_forced === true,
    };
  }
  if (row.triage_status === "unavailable") return UNAVAILABLE;
  return { kind: "pending" };
}

/**
 * The state of the ① column of the alert page, from `view.suggestion` the same way. A decided alert is
 * `decided` first (what ① said, if anything, is evaluation material once a person has decided); an
 * undecided one follows the row's rules, the key being `suggestion`.
 */
export function aiStateOfView(view: AlertView): AiState {
  const suggestion = view.suggestion;
  if (DECIDED.has(view.status)) {
    return {
      kind: "decided",
      action: typeof suggestion?.suggested_action === "string" ? suggestion.suggested_action : null,
      confidence: suggestion?.confidence ?? null,
    };
  }
  if (!("suggestion" in view) && view.suggestion_visible === false) return { kind: "hidden" };
  if (typeof suggestion?.suggested_action === "string") {
    return {
      kind: "ready",
      action: suggestion.suggested_action,
      confidence: suggestion.confidence ?? null,
      forced: suggestion.gate?.forced === true,
    };
  }
  if (view.triage_status === "unavailable") return UNAVAILABLE;
  return { kind: "pending" };
}
