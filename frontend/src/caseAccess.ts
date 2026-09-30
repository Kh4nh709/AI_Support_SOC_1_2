// Who may open the case pages (/cases, /cases/:id): Tier 2, and the admin who reads them too. One list, read by
// the route table (which shuts the pages to everyone else) and by the alert page (which links to a case only
// for a reader who could follow the link), so the two cannot part.
import type { Role } from "./api/types";

export const CASE_ROLES: readonly Role[] = ["tier2", "admin"];

/** No role (nobody signed in) is no access: the safe answer is the one that links nowhere. */
export const canOpenCases = (role: Role | null): boolean =>
  role !== null && CASE_ROLES.includes(role);
