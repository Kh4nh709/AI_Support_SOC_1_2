// Where a role starts, and where a login returns to (spec §3.1).
import type { Role } from "../api/types";

/** tier1 starts at the queue; tier2 and admin at the case list. */
export function roleHome(role: Role): string {
  return role === "tier1" ? "/queue" : "/cases";
}

/** The path, query and hash of a location: what `state.from` carries to the login page. */
export function pathOf(location: { pathname: string; search: string; hash: string }): string {
  return `${location.pathname}${location.search}${location.hash}`;
}

/** A `from` that stays inside the app: a path of this origin that is not the login page itself. */
function isLocalPath(from: unknown): from is string {
  return (
    typeof from === "string" &&
    from.startsWith("/") &&
    !from.startsWith("//") &&
    !from.startsWith("/\\") &&
    !/^\/login(?:[/?#]|$)/.test(from)
  );
}

/**
 * The page a successful login opens: the one the user was turned away from (`state.from`, set when a
 * guarded page found no session), or the role's home.
 */
export function landingAfterLogin(state: unknown, role: Role): string {
  const from = (state as { from?: unknown } | null)?.from;
  return isLocalPath(from) ? from : roleHome(role);
}
