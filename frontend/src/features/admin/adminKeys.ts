// The query keys of the admin pages, in one place, so a write knows which reads it makes stale (spec §3:
// TanStack Query owns every read, and every mutation invalidates the queries it touches).
// TanStack matches a key by its prefix: `["admin", "overview"]` is the overview of every range, and
// `["admin"]` is the whole console.
//
//   read                         key                                       fetched by
//   overview (24h|7d|30d)        adminKeys.overview(range)                 getOverview
//   users                        adminKeys.users                           listUsers
//   LLM usage and limits         adminKeys.llmUsage(range)                 getLlmUsage
//   auto-close rules             adminKeys.rules                           listRules
//   digest of one day            adminKeys.digest(day)                     getDigest (day null: today)
//   blind labelling              adminKeys.labels                          getLabelsNext
//   audit page                   adminKeys.audit(filters)                  getAudit
//   knowledge: a draft tab       adminKeys.knowledgeDrafts(status)         listKnowledgeDrafts
//   knowledge: an entry tab      adminKeys.knowledgeEntries(status)        listKnowledgeEntries
//   knowledge: one draft         adminKeys.knowledgeDraft(id)              getKnowledgeDraft
//   knowledge: one entry         adminKeys.knowledgeEntry(id)              getKnowledgeEntry
//   knowledge: the tag list      adminKeys.knowledgeTags                   getKnowledgeTags
//
// What each write invalidates is `ADMIN_INVALIDATES`; a page calls `invalidateAfter(client, "toggleRule")`
// in its mutation's `onSuccess`, and shows its toast. There are no optimistic updates.
import type { QueryClient } from "@tanstack/react-query";
import type {
  AdminRange,
  AuditFilters,
  KnowledgeDraftStatus,
  KnowledgeEntryStatus,
  LlmRange,
} from "../../api/admin";

export const adminKeys = {
  /** Every admin read. */
  all: ["admin"] as const,

  /** The overview of one range. */
  overview: (range: AdminRange) => ["admin", "overview", range] as const,
  /** The overview of every range. */
  overviewAll: ["admin", "overview"] as const,

  users: ["admin", "users"] as const,

  /** The LLM usage page of one range (it carries the limits panel too). */
  llmUsage: (range: LlmRange) => ["admin", "llm", "usage", range] as const,
  /** Everything of the LLM page, whatever the range. */
  llmAll: ["admin", "llm"] as const,

  rules: ["admin", "rules"] as const,

  /** The digest of one day; `null` is today, whose day is not in the URL. */
  digest: (day: string | null) => ["admin", "digest", day] as const,
  /** The digest of every day. */
  digestAll: ["admin", "digest"] as const,

  labels: ["admin", "labels"] as const,

  /** One page of the audit log under one filter set; the page's cursor is part of `filters`. */
  audit: (filters: AuditFilters) => ["admin", "audit", filters] as const,
  /** Every audit page, whatever the filters. */
  auditAll: ["admin", "audit"] as const,

  /** Everything of the learned-knowledge page: the lists of every tab, the details, the tags (DEC-210). */
  knowledgeAll: ["admin", "knowledge"] as const,
  /** The list of one draft tab (`pending`, `merged`, `rejected`). */
  knowledgeDrafts: (status: KnowledgeDraftStatus) =>
    ["admin", "knowledge", "drafts", status] as const,
  /** One draft with the analyst's work beside it. */
  knowledgeDraft: (draftId: string) => ["admin", "knowledge", "draft", draftId] as const,
  /** The list of one entry tab (`active`, `retired`). */
  knowledgeEntries: (status: KnowledgeEntryStatus) =>
    ["admin", "knowledge", "entries", status] as const,
  /** One entry with its Markdown. */
  knowledgeEntry: (entryId: string) => ["admin", "knowledge", "entry", entryId] as const,
  /** The closed tag vocabulary: it changes with a deploy, not with a write. */
  knowledgeTags: ["admin", "knowledge", "tags"] as const,
};

/**
 * Every write of `api/admin.ts` that changes something, and the reads it makes stale, by prefix.
 * - Each write touches the read of its own page.
 * - Each also touches the audit page (`auditAll`), which shows the event it wrote.
 * - The overview shows counts that other pages change: the inventory (a reload), the failed jobs (a retry),
 *   the LLM cost against the cap (a limit change), the funnel (a digest review reopens an alert).
 * - The digest shows "no rule enabled" from `rules_enabled`, which a rule created or toggled changes, so the
 *   two rule writes touch the digest of every day (`digestAll`) too.
 */
export const ADMIN_INVALIDATES = {
  retryJob: [adminKeys.overviewAll, adminKeys.auditAll],
  reloadInventory: [adminKeys.overviewAll],
  createUser: [adminKeys.users, adminKeys.auditAll],
  updateUser: [adminKeys.users, adminKeys.auditAll],
  resetPassword: [adminKeys.users, adminKeys.auditAll],
  unlockUser: [adminKeys.users, adminKeys.auditAll],
  putLlmLimits: [adminKeys.llmAll, adminKeys.overviewAll, adminKeys.auditAll],
  createRule: [adminKeys.rules, adminKeys.digestAll, adminKeys.auditAll],
  toggleRule: [adminKeys.rules, adminKeys.digestAll, adminKeys.auditAll],
  reviewDigest: [adminKeys.digestAll, adminKeys.overviewAll, adminKeys.auditAll],
  postLabel: [adminKeys.labels, adminKeys.auditAll],
  undoLabel: [adminKeys.labels, adminKeys.auditAll],
  // A draft leaves its tab (and an entry is born, or retired), the overview counts the drafts that wait, and the
  // audit page shows the event; the tag list does not change, and is refetched with the rest, which costs nothing.
  approveKnowledgeDraft: [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll],
  rejectKnowledgeDraft: [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll],
  retireKnowledgeEntry: [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll],
} as const;

export type AdminMutation = keyof typeof ADMIN_INVALIDATES;

/** The names of the writes, for a test that every write has a row. */
export const ADMIN_MUTATIONS = Object.keys(ADMIN_INVALIDATES) as AdminMutation[];

/** Marks the reads a write touched as stale, and refetches the ones on screen. Settles when they have. */
export async function invalidateAfter(client: QueryClient, mutation: AdminMutation): Promise<void> {
  await Promise.all(
    ADMIN_INVALIDATES[mutation].map((queryKey) => client.invalidateQueries({ queryKey })),
  );
}
