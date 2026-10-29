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

/**
 * The statuses in which the server shows the ① verdict to everyone (visibility.SHOW_STATES). A copy: the
 * test of this file reads the Python source and compares the two sets, so a status added on one side fails.
 */
export const DECIDED: ReadonlySet<string> = new Set([
  "closed_fp",
  "closed_benign",
  "closed_confirmed",
  "escalated_tier2",
  "auto_closed",
]);

// The alert view says why ① gave up (`llm_stopped_by`, the `stopped_by` of the newest ① run: INT-T02), and
// `aiStateOfView` passes it on. The queue row does not: it carries no `stopped_by`, so a row's `unavailable`
// names no reason, and the alert page is where it is worded.
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
  if (
    !("suggested_action" in row) &&
    row.suggestion_visible === false &&
    !DECIDED.has(row.status)
  ) {
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
 * undecided one follows the row's rules, the key being `suggestion`. `unavailable` carries the view's
 * `llm_stopped_by` (the reason, null when the view has none). It is read only after the blind check, and the
 * server drops it from a blind head, so no reason ever reaches the hidden state.
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
  if (view.triage_status === "unavailable") {
    const stoppedBy = view.llm_stopped_by;
    return typeof stoppedBy === "string" ? { kind: "unavailable", stoppedBy } : UNAVAILABLE;
  }
  return { kind: "pending" };
}
