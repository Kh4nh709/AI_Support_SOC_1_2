// The one place the ① state is decided, for a queue row and for the alert view (P10-T09; the alert page,
// P10-T10, reuses it). The blind arm (DEC-101) is read from the response only: the server drops the ①
// keys from a blind, undecided head, and this file recognises that. It never fetches, infers or caches a
// suggestion any other way, so a component that wants to know "what does ① say" asks here and nowhere else.
import type { AlertView, QueueRow, SuggestionGate } from "../../api/tier1";

/**
 * What ① concluded and which of the gate's checks warned about it (P14-T03, DEC-213; DEC-217; DEC-219): the part of a
 * `ready` and of a `decided` state that the conclusion line ("AI kết luận: …") is made of. `action` is the verdict ①
 * ends with (`suggested_action`: `false_positive` or `true_positive`; the model's own answer, except for a run below
 * the RAG threshold, below; the server never serves `needs_review` for ①), `proposed` what the server calls the
 * model's answer (`proposed_action`, null when it sent none; for a run below the threshold it is the verdict ① ended
 * with, never the model's own), `heldBy` the closed codes of `llm.verdicts.HELD_REASONS` that name the checks that
 * raised a warning (`[]` when none did). The name `heldBy` is the wire's (`held_by`); since DEC-217 it holds a
 * warning, not a hold.
 *
 * `ragDefaultBelow` is there only for a run the RAG rule applied to (DEC-219): a RAG match existed and its best was
 * below this percentage, so `false_positive` is ①'s default answer, whether the model had said it itself or not. The
 * alert view says so (`suggestion.gate.rag_rule.applied`) and the verdict it serves is `false_positive`; the queue row
 * carries nothing of it, and any other run has no such key.
 */
export type AiConclusion = {
  action: string | null;
  proposed: string | null;
  heldBy: string[];
  ragDefaultBelow?: number;
};

export type AiState =
  | ({
      kind: "ready";
      action: string;
      confidence: string | null;
      forced: boolean;
    } & AiConclusion)
  | { kind: "hidden" }
  | { kind: "pending" }
  | { kind: "none" }
  | { kind: "unavailable"; stoppedBy: string | null }
  | ({ kind: "decided"; confidence: string | null } & AiConclusion);

/**
 * What the model may answer (`llm.verdicts.MODEL_ACTIONS`, P14-T01): ① always concludes one of the two. A copy:
 * the test of this file reads the Python source and compares the two, so an answer added on one side fails.
 */
export const MODEL_ACTIONS: ReadonlySet<string> = new Set(["false_positive", "true_positive"]);

/**
 * What the AI concluded, for the line "AI kết luận: …": the verdict ① ended with (`action`) when it is one of the two
 * the model may give (every run: the model's own answer, DEC-217, or the verdict the RAG rule made of it, DEC-219),
 * else the model's own answer (`proposed`) when that is one of them, else null. The second reading is the guard for a
 * `needs_review` stored before DEC-217 that still arrives from an old cache, and for a decided state with no action;
 * a `needs_review` nobody explained is the system's word, not a conclusion.
 */
export function conclusionOf(state: AiConclusion): string | null {
  if (state.action !== null && MODEL_ACTIONS.has(state.action)) return state.action;
  return state.proposed !== null && MODEL_ACTIONS.has(state.proposed) ? state.proposed : null;
}

/**
 * Whether the gate's checks raised a warning beside the verdict: a reason is named (`heldBy`). The second half, a
 * stored `needs_review`, is only a guard for an old client cache or a server that predates DEC-217: ① never ends
 * `needs_review` for a new run, and nothing is held back for a person.
 */
export function heldOf(state: AiConclusion): boolean {
  return state.action === "needs_review" || state.heldBy.length > 0;
}

/** A list of reason codes as it arrives: only its non-empty strings; anything else is none. */
function codes(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((x): x is string => typeof x === "string" && x !== "")
    : [];
}

const textOrNull = (value: unknown): string | null => (typeof value === "string" ? value : null);

/**
 * The RAG rule of DEC-219, as the key of an `AiConclusion` it belongs to: `ragDefaultBelow` when the gate says the rule
 * applied to this run (`rag_rule.applied` is true, with the threshold the match was below), and no key at all for any
 * other run: a rule that did not apply or was switched off, a run stored before the rule (`rag_rule` null or absent),
 * and a value that is not what the server sends. `changed` is not read: whether the model had said `false_positive`
 * itself or the rule made it, the page says the same. The default is `false_positive`, so a run whose verdict is
 * anything else (an inconsistent server) announces none: its line is today's. Only the alert view's gate carries it,
 * so only `aiStateOfView` reads it.
 */
function ragRuleOf(
  gate: SuggestionGate | null | undefined,
  action: string | null,
): { ragDefaultBelow?: number } {
  const rule: unknown = gate?.rag_rule;
  if (action !== "false_positive" || typeof rule !== "object" || rule === null) return {};
  const { applied, threshold } = rule as Record<string, unknown>;
  return applied === true &&
    typeof threshold === "number" &&
    Number.isFinite(threshold) &&
    threshold > 0
    ? { ragDefaultBelow: threshold }
    : {};
}

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

/**
 * An archived alert (021, DEC-212) was closed out without review and its `triage` job is skipped when it runs, so
 * a ① that had not answered by then never will: its `triage_status` stays `pending` for good. It is the one status
 * that turns "no result yet" into `none` ("chưa có") instead of `pending` ("Đang phân tích…", and a page that polls
 * for the answer every ten seconds). The blind-arm rule is read first and the other states are unchanged.
 */
const ARCHIVED = "archived";

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
 *  - Otherwise `pending`: the visible arm, no result yet; `none` when the alert is archived (see `ARCHIVED`).
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
      proposed: textOrNull(row.proposed_action),
      heldBy: codes(row.held_by),
    };
  }
  if (row.triage_status === "unavailable") return UNAVAILABLE;
  return row.status === ARCHIVED ? { kind: "none" } : { kind: "pending" };
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
    const action =
      typeof suggestion?.suggested_action === "string" ? suggestion.suggested_action : null;
    return {
      kind: "decided",
      action,
      confidence: suggestion?.confidence ?? null,
      // The decision lifts the blind arm: the server sends the two keys back with the rest of the suggestion.
      proposed: textOrNull(view.proposed_action),
      heldBy: codes(view.held_by),
      ...ragRuleOf(suggestion?.gate, action),
    };
  }
  if (!("suggestion" in view) && view.suggestion_visible === false) return { kind: "hidden" };
  if (typeof suggestion?.suggested_action === "string") {
    return {
      kind: "ready",
      action: suggestion.suggested_action,
      confidence: suggestion.confidence ?? null,
      forced: suggestion.gate?.forced === true,
      proposed: textOrNull(view.proposed_action),
      heldBy: codes(view.held_by),
      ...ragRuleOf(suggestion.gate, suggestion.suggested_action),
    };
  }
  if (view.triage_status === "unavailable") {
    const stoppedBy = view.llm_stopped_by;
    return typeof stoppedBy === "string" ? { kind: "unavailable", stoppedBy } : UNAVAILABLE;
  }
  return view.status === ARCHIVED ? { kind: "none" } : { kind: "pending" };
}
