// Where a role starts, and where a login returns to (spec §3.1).
import type { Role } from "../api/types";

/** tier1 starts at the queue, tier2 at the case list, admin at the console's overview (admin spec, decision 7). */
export function roleHome(role: Role): string {
  if (role === "tier1") return "/queue";
  return role === "admin" ? "/admin/overview" : "/cases";
}

/** The path, query and hash of a location: what `state.from` carries to the login page. */
export function pathOf(location: { pathname: string; search: string; hash: string }): string {
  return `${location.pathname}${location.search}${location.hash}`;
}

/** A control character: U+0000 to U+001F and U+007F. Written as a scan, not a regex (`no-control-regex`). */
function hasControlCharacter(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/**
 * A `from` that stays inside the app: a path of this origin that is not the login page itself.
 *
 * The character rules come first, on the text as it was written: a URL parser silently drops a tab or a
 * newline and reads a backslash as a slash, so `/\t/evil.example` and `/\evil.example` both become
 * `//evil.example` for a browser. The parser then has the last word: whatever it resolves off this origin, or
 * to a scheme other than http and https, is refused.
 */
function isLocalPath(from: unknown): from is string {
  if (typeof from !== "string" || !from.startsWith("/")) return false;
  if (from.startsWith("//") || from.includes("\\") || hasControlCharacter(from)) return false;
  if (/^\/login(?:[/?#]|$)/.test(from)) return false;
  try {
    const origin = window.location.origin;
    const url = new URL(from, origin);
    return url.origin === origin && (url.protocol === "http:" || url.protocol === "https:");
  } catch {
    return false; // no origin to compare with, or text the parser refuses
  }
}

/**
 * The page a successful login opens: the one the user was turned away from (`state.from`, set when a
 * guarded page found no session), or the role's home.
 */
export function landingAfterLogin(state: unknown, role: Role): string {
  const from = (state as { from?: unknown } | null)?.from;
  return isLocalPath(from) ? from : roleHome(role);
}
