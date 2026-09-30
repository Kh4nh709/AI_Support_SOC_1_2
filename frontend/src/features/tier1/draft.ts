// The reason an analyst is typing, kept in this tab's sessionStorage so that a lost session (a 401) does not
// lose it (Review Focus 4): `soc.draft.<alert_id>` = JSON `{user_id, text}`. It is restored only for the
// user who typed it (a draft left by someone else on a shared browser is never shown to the next one), it
// is removed when the decision goes through, and it lives in the tab's own store only, never in a store
// that outlives the tab (ruling R5). The session key `soc.session` is not touched here or by the logout,
// which removes that key alone.
import { sameUser } from "./useMe";

const PREFIX = "soc.draft.";

export const draftKey = (alertId: string): string => `${PREFIX}${alertId}`;

/** The draft of this user for this alert, or "" when there is none, it is somebody else's, or it is unreadable. */
export function readDraft(alertId: string, userId: string): string {
  try {
    const raw = sessionStorage.getItem(draftKey(alertId));
    if (raw === null) return "";
    const value: unknown = JSON.parse(raw);
    if (typeof value !== "object" || value === null) return "";
    const { user_id: owner, text } = value as Record<string, unknown>;
    if (typeof owner !== "string" || typeof text !== "string") return "";
    return sameUser(owner, userId) ? text : "";
  } catch {
    return "";
  }
}

/** Keeps what has been typed; an empty box keeps nothing. */
export function writeDraft(alertId: string, userId: string, text: string): void {
  try {
    if (text === "") sessionStorage.removeItem(draftKey(alertId));
    else sessionStorage.setItem(draftKey(alertId), JSON.stringify({ user_id: userId, text }));
  } catch {
    // storage is full or blocked: the draft is a convenience, and the reason is still in the box
  }
}

export function clearDraft(alertId: string): void {
  try {
    sessionStorage.removeItem(draftKey(alertId));
  } catch {
    // nothing to remove from a store that cannot be read
  }
}
