// The two preferences of the SOAR page that outlive the tab, and the only code of this UI that touches the store that
// does: whether the new-ticket signal is on (`soc.soar.signal`), and which notices were dismissed
// (`soc.soar.dismissed`, a JSON list of ids, newest last). Neither is a secret and neither names a person: the session
// and the token never come near this file (src/guards.test.ts holds ruling R5 for every other file, and reads this one
// to prove it imports nothing of the session). The store can be missing, full, blocked or filled by hand, so every read
// and every write is inside try/catch, and the page works without it.

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

export function readSignalOn(): boolean {
  try {
    return localStorage.getItem(SIGNAL_KEY) === "1";
  } catch {
    return false;
  }
}

export function writeSignalOn(on: boolean): void {
  try {
    localStorage.setItem(SIGNAL_KEY, on ? "1" : "0");
  } catch {
    // blocked or full: the switch works for this visit, and is off again at the next
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
    const raw = localStorage.getItem(DISMISSED_KEY);
    if (raw === null) return [];
    const value: unknown = JSON.parse(raw);
    return Array.isArray(value) ? capped(value) : [];
  } catch {
    return [];
  }
}

export function writeDismissed(ids: readonly string[]): void {
  try {
    localStorage.setItem(DISMISSED_KEY, JSON.stringify(capped(ids)));
  } catch {
    // blocked or full: the notice stays dismissed until the tab is closed
  }
}
