// What the SOAR page works out of a review, with no React in it: the colour of a score, the words of a status and an
// action, the buttons a person may press, the countdown and the reminder of a row. Everything that came from n8n is
// read defensively (a null, a number where text should be, an unknown code), and nothing is ever dropped for being
// unknown: it is shown as its code.
import {
  SOAR_DECISIONS,
  type SoarActionType,
  type SoarDecision,
  type SoarReview,
} from "../../api/soar";
import { formatClock } from "../../format";
import { S, labelOf } from "../../strings";

/** The longest note a decision carries (spec section 4). */
export const NOTE_MAX = 500;

export type Tone = "critical" | "high" | "medium";

/** Red from 70, orange from 40, yellow below (the number is always printed too: colour is never the only carrier). */
export function scoreTone(score: number): Tone {
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  return "medium";
}

// Whole class names, written out: Tailwind finds a class by reading the source.
export const SCORE_CLASS: Record<Tone, string> = {
  critical: "border-critical text-critical",
  high: "border-high text-high",
  medium: "border-medium text-medium",
};

const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

/** The word of a status; a row another person holds says who. A status with no word is the code. */
export function statusText(review: Pick<SoarReview, "status" | "locked_by">): string {
  if (review.status === "processing") {
    const who = text(review.locked_by);
    if (who !== null) return S.soar.heldBy(who);
  }
  return labelOf(S.soar.status, review.status);
}

/** n8n's own text of the action; failing that, the word of its type; failing that, the code. */
export function actionTextOf(review: Pick<SoarReview, "action_text" | "action_type">): string {
  return text(review.action_text) ?? labelOf(S.soar.actionType, review.action_type);
}

export type ShownButton = { decision: SoarDecision; label: string };

const isDecision = (value: unknown): value is SoarDecision =>
  typeof value === "string" && (SOAR_DECISIONS as readonly string[]).includes(value);

/**
 * One button per entry of `buttons` whose `decision` is in `allowed_decisions` (which the server worked out for this
 * caller: valid for the state AND allowed for the role), labelled with n8n's text. A decision this UI cannot send is
 * no button; a blank label falls back to the word of the decision.
 */
export function buttonsOf(
  review: Pick<SoarReview, "buttons" | "allowed_decisions">,
): ShownButton[] {
  const allowed: unknown = review.allowed_decisions;
  const buttons: unknown = review.buttons;
  if (!Array.isArray(allowed) || !Array.isArray(buttons)) return [];
  const shown: ShownButton[] = [];
  for (const entry of buttons as unknown[]) {
    if (typeof entry !== "object" || entry === null) continue;
    const { decision, label } = entry as { decision?: unknown; label?: unknown };
    if (!isDecision(decision) || !allowed.includes(decision)) continue;
    shown.push({ decision, label: text(label) ?? S.soar.decision[decision] });
  }
  return shown;
}

/** "59:58", or "1:02:05" from an hour up; never below zero. */
export function formatCountdown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const two = (n: number) => String(n).padStart(2, "0");
  return hours > 0 ? `${hours}:${two(minutes)}:${two(seconds)}` : `${two(minutes)}:${two(seconds)}`;
}

export type Timers = {
  /** The auto-undo: counting down, or past with the ticket still open. */
  expiry: { kind: "ahead"; clock: string; left: string } | { kind: "past" } | null;
  /** An isolation or a locked account that is being held, with its reminder interval. */
  hold: { minutes: number; due: boolean } | null;
};

const HELD_ACTIONS: readonly SoarActionType[] = ["isolate_host", "disable_user"];
/** The states in which the measure is still on: an undone or expired ticket holds nothing. */
const HOLDING = new Set(["open", "processing", "kept"]);

const timeOf = (iso: unknown): number | null => {
  if (typeof iso !== "string") return null;
  const at = Date.parse(iso);
  return Number.isNaN(at) ? null : at;
};

/**
 * The timers of a row at `nowMs`. The web never changes a status itself: a time that has passed on a ticket that is
 * still open only says the SOAR has yet to close it.
 */
export function timersOf(review: SoarReview, nowMs: number): Timers {
  if (review.kind !== "review") return { expiry: null, hold: null };
  let expiry: Timers["expiry"] = null;
  const expireAt = timeOf(review.auto_expire_at);
  if (expireAt !== null && (review.status === "open" || review.status === "processing")) {
    if (expireAt > nowMs) {
      expiry = {
        kind: "ahead",
        clock: formatClock(review.auto_expire_at),
        left: formatCountdown(expireAt - nowMs),
      };
    } else if (review.status === "open") {
      expiry = { kind: "past" };
    }
  }
  let hold: Timers["hold"] = null;
  const minutes = review.remind_every_minutes;
  if (
    review.action_type !== null &&
    HELD_ACTIONS.includes(review.action_type) &&
    typeof minutes === "number" &&
    minutes > 0 &&
    HOLDING.has(review.status)
  ) {
    const next = timeOf(review.next_remind_at);
    hold = { minutes, due: next !== null && next <= nowMs };
  }
  return { expiry, hold };
}
