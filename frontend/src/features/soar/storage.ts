// The two preferences of the SOAR page, kept in THIS TAB's session store, as the alert page keeps its draft
// (features/tier1/draft.ts): whether the new-ticket signal was turned on or off in this tab (`soc.soar.signal`, "1" or "0"),
// and which notices were dismissed in it (`soc.soar.dismissed`, a JSON list of ids, newest last). Both live and die with the
// tab; nothing is written to a store that outlives it (ruling R5, src/guards.test.ts). Neither is a secret and neither names
// a person. The store can be missing, full, blocked or filled by hand, so every read and every write is inside try/catch, the
// page works without it, and nothing read back is believed until it has the shape that was written.
// Both are one person's choices: auth/session.ts names the two keys (`PER_SESSION_KEYS`, held equal to these by a test) and removes
// them with the session, so the next person to sign in in the same tab starts from the default.

export const SIGNAL_KEY = "soc.soar.signal";
export const DISMISSED_KEY = "soc.soar.dismissed";
/** The most dismissed ids kept: the newest ones, so the list cannot grow without bound. */
export const DISMISSED_CAP = 200;
/**
 * The shape of the id of a notice (spec section 2): N and twelve letters, digits, `_` or `-`. It is all this file keeps of a
 * dismissed notice, on the way in and on the way out: a store somebody filled by hand, or a call with a token, a path or a
 * review id, keeps nothing of it.
 */
export const NOTICE_ID = /^N[A-Za-z0-9_-]{12}$/;

/**
 * What this tab chose for the signal: true (on), false (off), or null when it has not chosen (or the store cannot say, or
 * holds anything but the two values written): the default of the browser's permission then stands (signal.ts).
 */
export function readSignalChoice(): boolean | null {
  try {
    const raw = sessionStorage.getItem(SIGNAL_KEY);
    return raw === "1" ? true : raw === "0" ? false : null;
  } catch {
    return null;
  }
}

export function writeSignalOn(on: boolean): void {
  try {
    sessionStorage.setItem(SIGNAL_KEY, on ? "1" : "0");
  } catch {
    // blocked or full: the switch works for this visit, and the default stands at the next
  }
}

/** The last `DISMISSED_CAP` distinct ids of `ids`, in order, the later one of a repeated id counting. */
function capped(ids: readonly unknown[]): string[] {
  const kept: string[] = [];
  for (const id of ids) {
    if (typeof id !== "string" || !NOTICE_ID.test(id)) continue;
    const at = kept.indexOf(id);
    if (at !== -1) kept.splice(at, 1);
    kept.push(id);
  }
  return kept.slice(-DISMISSED_CAP);
}

export function readDismissed(): string[] {
  try {
    const raw = sessionStorage.getItem(DISMISSED_KEY);
    if (raw === null) return [];
    const value: unknown = JSON.parse(raw);
    return Array.isArray(value) ? capped(value) : [];
  } catch {
    return [];
  }
}

export function writeDismissed(ids: readonly string[]): void {
  try {
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify(capped(ids)));
  } catch {
    // blocked or full: the notice stays dismissed until the page is left
  }
}
