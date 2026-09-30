// The session: `{token, role, username, expiresAt}`, held in memory by AuthProvider, mirrored to
// sessionStorage under one key, and shared with the other tabs of the browser over a BroadcastChannel
// (spec §3). It is never written to any persistent store and never put in a URL.
//
// sessionStorage belongs to one tab, so a tab opened by a link (an alert in a new tab) has none. It asks
// the open tabs over the channel, and any tab that has a session answers with it. A logout is broadcast,
// and every tab that hears it closes its own session.
import { isRole, type Role } from "../api/types";

export type Session = {
  token: string;
  role: Role;
  username: string;
  /** ISO 8601, the token's `exp`. */
  expiresAt: string;
};

const KEY = "soc.session";
const CHANNEL = "soc-session";

/** The protocol of the channel. Anything else that arrives on it is ignored. */
type Message =
  { type: "session-request" } | { type: "session"; session: unknown } | { type: "logout" };

/** A session that has the right shape and has not expired, or null. Never throws. */
function parseSession(value: unknown): Session | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.token !== "string" || v.token === "") return null;
  if (!isRole(v.role)) return null;
  if (typeof v.username !== "string") return null;
  if (typeof v.expiresAt !== "string") return null;
  const expires = Date.parse(v.expiresAt);
  if (Number.isNaN(expires) || expires <= Date.now()) return null;
  return { token: v.token, role: v.role, username: v.username, expiresAt: v.expiresAt };
}

function isMessage(value: unknown): value is Message {
  if (typeof value !== "object" || value === null) return false;
  const type = (value as { type?: unknown }).type;
  return type === "session-request" || type === "session" || type === "logout";
}

function openChannel(): BroadcastChannel | null {
  return typeof BroadcastChannel === "undefined" ? null : new BroadcastChannel(CHANNEL);
}

/** The stored session of this tab; null when there is none, it is unreadable, or it has expired. */
export function loadSession(): Session | null {
  let raw: string | null;
  try {
    raw = sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = null;
  }
  const session = parseSession(parsed);
  if (session === null) forgetSession(); // an expired or malformed entry is dead weight
  return session;
}

/** Mirrors the session to this tab's sessionStorage, and nowhere else. */
export function saveSession(s: Session): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    // Storage refused (a full or disabled store): the session still lives in memory for this tab.
  }
}

/** Empties this tab's stored session and says nothing to the other tabs. */
export function forgetSession(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // Nothing to remove from a store that cannot be read.
  }
}

/** Logout: empties this tab's stored session and tells every other tab to close theirs. */
export function clearSession(): void {
  forgetSession();
  const channel = openChannel();
  if (channel === null) return;
  channel.postMessage({ type: "logout" } satisfies Message);
  channel.close();
}

/**
 * Makes this tab a member of the sharing: it answers a `session-request` with its stored session, and on a
 * `logout` it forgets its session (without broadcasting again, which would ping-pong between the tabs) and
 * calls `onLogout`. Returns the function that stops it.
 */
export function startSessionSharing(onLogout: () => void): () => void {
  const channel = openChannel();
  if (channel === null) return () => {};
  channel.onmessage = (event: MessageEvent<unknown>) => {
    const message = event.data;
    if (!isMessage(message)) return;
    if (message.type === "session-request") {
      const session = loadSession();
      if (session !== null) channel.postMessage({ type: "session", session } satisfies Message);
    } else if (message.type === "logout") {
      forgetSession();
      onLogout();
    }
  };
  return () => {
    channel.onmessage = null;
    channel.close();
  };
}

/**
 * Asks the other open tabs for their session. Resolves with the first valid, unexpired one, or with null
 * when none answers within `timeoutMs` or `signal` aborts. The caller saves what it gets.
 */
export function requestSessionFromOtherTabs(
  timeoutMs = 300,
  signal?: AbortSignal,
): Promise<Session | null> {
  const channel = openChannel();
  if (channel === null || signal?.aborted) {
    channel?.close();
    return Promise.resolve(null);
  }
  return new Promise((resolve) => {
    const finish = (session: Session | null) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      channel.onmessage = null;
      channel.close();
      resolve(session);
    };
    const onAbort = () => finish(null);
    const timer = setTimeout(() => finish(null), timeoutMs);
    signal?.addEventListener("abort", onAbort);
    channel.onmessage = (event: MessageEvent<unknown>) => {
      const message = event.data;
      if (!isMessage(message) || message.type !== "session") return;
      const session = parseSession(message.session);
      if (session !== null) finish(session);
    };
    channel.postMessage({ type: "session-request" } satisfies Message);
  });
}
