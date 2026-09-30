// The query keys of the Tier-2 pages, in one place, so a write knows which reads it makes stale.
// TanStack matches a key by its prefix: `["cases"]` is every page of the list, `["case", id]` is one case,
// and `["investigation", id]` is every read of that case's ② column, whatever run it named.

export const tier2Keys = {
  /** Every page of the case list. */
  cases: ["cases"] as const,
  /** One page of the case list, 0-based. */
  casesPage: (page: number) => ["cases", page] as const,
  /** One case: its heads, notes and conclusion. */
  case: (caseId: string) => ["case", caseId] as const,
  /** Every read of the ② column of one case. */
  investigations: (caseId: string) => ["investigation", caseId] as const,
  /** The ② column of one case, read with the run of the 202 (or none). */
  investigation: (caseId: string, runId: string | null) =>
    ["investigation", caseId, runId] as const,
};
