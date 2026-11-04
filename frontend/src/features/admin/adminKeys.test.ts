// src/features/admin/adminKeys.test.ts — the query keys of the admin pages, and what each write makes stale.
import { QueryClient } from "@tanstack/react-query";
import {
  ADMIN_INVALIDATES,
  ADMIN_MUTATIONS,
  adminKeys,
  invalidateAfter,
  type AdminMutation,
} from "./adminKeys";

describe("adminKeys", () => {
  it("has the five keys of the spec that stay", () => {
    expect(adminKeys.overview("24h")).toEqual(["admin", "overview", "24h"]);
    expect(adminKeys.users).toEqual(["admin", "users"]);
    expect(adminKeys.llmUsage("month")).toEqual(["admin", "llm", "usage", "month"]);
    expect(adminKeys.labels).toEqual(["admin", "labels"]);
    expect(adminKeys.audit({ range: "7d", group: "users" })).toEqual([
      "admin",
      "audit",
      { range: "7d", group: "users" },
    ]);
  });

  // DEC-214: the auto-close pages are gone, and with them their reads. No key is left for a cache entry to sit under.
  it("has no key for the removed rules and digest pages", () => {
    expect(Object.keys(adminKeys)).not.toContain("rules");
    expect(Object.keys(adminKeys)).not.toContain("digest");
    expect(Object.keys(adminKeys)).not.toContain("digestAll");
    expect(Object.keys(adminKeys).sort()).toEqual(
      [
        "all",
        "audit",
        "auditAll",
        "knowledgeAll",
        "knowledgeDraft",
        "knowledgeDrafts",
        "knowledgeEntries",
        "knowledgeEntry",
        "knowledgeTags",
        "labels",
        "llmAll",
        "llmUsage",
        "overview",
        "overviewAll",
        "users",
      ].sort(),
    );
  });

  it("has the five keys of the learned-knowledge page, under one prefix", () => {
    expect(adminKeys.knowledgeAll).toEqual(["admin", "knowledge"]);
    expect(adminKeys.knowledgeDrafts("pending")).toEqual([
      "admin",
      "knowledge",
      "drafts",
      "pending",
    ]);
    expect(adminKeys.knowledgeDraft("d-1")).toEqual(["admin", "knowledge", "draft", "d-1"]);
    expect(adminKeys.knowledgeEntries("active")).toEqual([
      "admin",
      "knowledge",
      "entries",
      "active",
    ]);
    expect(adminKeys.knowledgeEntry("e-1")).toEqual(["admin", "knowledge", "entry", "e-1"]);
    expect(adminKeys.knowledgeTags).toEqual(["admin", "knowledge", "tags"]);
    // two statuses, two lists: a tab never shows another tab's rows
    expect(adminKeys.knowledgeDrafts("pending")).not.toEqual(adminKeys.knowledgeDrafts("merged"));
    expect(adminKeys.knowledgeEntries("active")).not.toEqual(adminKeys.knowledgeEntries("retired"));
    const starts = (key: readonly unknown[], prefix: readonly unknown[]) =>
      prefix.every((part, i) => key[i] === part);
    for (const key of [
      adminKeys.knowledgeDrafts("rejected"),
      adminKeys.knowledgeDraft("d-1"),
      adminKeys.knowledgeEntries("retired"),
      adminKeys.knowledgeEntry("e-1"),
      adminKeys.knowledgeTags,
    ]) {
      expect(starts(key, adminKeys.knowledgeAll)).toBe(true);
    }
  });

  it("starts every key with admin, so one prefix reaches the whole console", () => {
    const all = [
      adminKeys.overview("24h"),
      adminKeys.users,
      adminKeys.llmUsage("7d"),
      adminKeys.labels,
      adminKeys.audit({ range: "24h" }),
      adminKeys.knowledgeDrafts("pending"),
      adminKeys.knowledgeEntry("e-1"),
    ];
    for (const key of all) expect(key[0]).toBe("admin");
    expect(adminKeys.all).toEqual(["admin"]);
  });

  it("has a prefix for each key that carries an argument, which every argument's key starts with", () => {
    const starts = (key: readonly unknown[], prefix: readonly unknown[]) =>
      prefix.every((part, i) => key[i] === part);
    for (const range of ["24h", "7d", "30d"] as const) {
      expect(starts(adminKeys.overview(range), adminKeys.overviewAll)).toBe(true);
      expect(starts(adminKeys.audit({ range }), adminKeys.auditAll)).toBe(true);
    }
    for (const range of ["24h", "7d", "30d", "month"] as const) {
      expect(starts(adminKeys.llmUsage(range), adminKeys.llmAll)).toBe(true);
    }
  });

  it("separates two filter sets of the audit page", () => {
    expect(adminKeys.audit({ range: "7d" })).not.toEqual(adminKeys.audit({ range: "30d" }));
  });
});

describe("what a write makes stale", () => {
  it("names every write of the client, once", () => {
    expect([...ADMIN_MUTATIONS].sort()).toEqual(
      [
        "approveKnowledgeDraft",
        "createUser",
        "postLabel",
        "putLlmLimits",
        "redraftKnowledgeDraft",
        "rejectKnowledgeDraft",
        "reloadInventory",
        "resetPassword",
        "retireKnowledgeEntry",
        "retryJob",
        "undoLabel",
        "unlockUser",
        "updateUser",
      ].sort(),
    );
  });

  // Each row: the write, then the keys of the reads it touches (the spec §3: every mutation
  // invalidates the queries it touches).
  const EXPECTED: [AdminMutation, readonly (readonly unknown[])[]][] = [
    ["retryJob", [adminKeys.overviewAll, adminKeys.auditAll]],
    ["reloadInventory", [adminKeys.overviewAll]],
    ["createUser", [adminKeys.users, adminKeys.auditAll]],
    ["updateUser", [adminKeys.users, adminKeys.auditAll]],
    ["resetPassword", [adminKeys.users, adminKeys.auditAll]],
    ["unlockUser", [adminKeys.users, adminKeys.auditAll]],
    ["putLlmLimits", [adminKeys.llmAll, adminKeys.overviewAll, adminKeys.auditAll]],
    ["postLabel", [adminKeys.labels, adminKeys.auditAll]],
    ["undoLabel", [adminKeys.labels, adminKeys.auditAll]],
    // The knowledge page's every list and detail (a draft leaves one tab for another, an entry is born or retired),
    // the overview's pending and conflict counts, and the audit page that shows the event.
    ["approveKnowledgeDraft", [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll]],
    ["rejectKnowledgeDraft", [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll]],
    ["redraftKnowledgeDraft", [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll]],
    ["retireKnowledgeEntry", [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll]],
  ];

  it.each(EXPECTED)("%s invalidates its keys", async (mutation, keys) => {
    const client = new QueryClient();
    const invalidated: unknown[] = [];
    client.invalidateQueries = ((filters: { queryKey?: unknown }) => {
      invalidated.push(filters.queryKey);
      return Promise.resolve();
    }) as typeof client.invalidateQueries;
    await invalidateAfter(client, mutation);
    expect(invalidated).toEqual(keys);
  });

  it("marks a cached read stale and leaves an unrelated one alone", async () => {
    const client = new QueryClient();
    client.setQueryData(adminKeys.users, { users: [] });
    client.setQueryData(adminKeys.labels, {});
    client.setQueryData(adminKeys.audit({ range: "7d" }), { events: [] });
    await invalidateAfter(client, "updateUser");
    expect(client.getQueryState(adminKeys.users)?.isInvalidated).toBe(true);
    expect(client.getQueryState(adminKeys.audit({ range: "7d" }))?.isInvalidated).toBe(true);
    expect(client.getQueryState(adminKeys.labels)?.isInvalidated).toBe(false);
  });

  // DEC-214: no write of the removed pages is left in the table, and none of the others names a key that is gone.
  it("has no write for the removed rules and digest pages, and no write touches their keys", () => {
    expect(ADMIN_MUTATIONS).not.toContain("createRule");
    expect(ADMIN_MUTATIONS).not.toContain("toggleRule");
    expect(ADMIN_MUTATIONS).not.toContain("reviewDigest");
    for (const mutation of ADMIN_MUTATIONS) {
      for (const key of ADMIN_INVALIDATES[mutation]) {
        expect(key[0], mutation).toBe("admin");
        expect(key.length, mutation).toBeGreaterThan(0);
        expect(key[1], `${mutation} ${JSON.stringify(key)}`).not.toMatch(/^(rules|digest)$/);
      }
    }
  });

  it.each([
    "approveKnowledgeDraft",
    "rejectKnowledgeDraft",
    "redraftKnowledgeDraft",
    "retireKnowledgeEntry",
  ] as const)(
    "%s refreshes every tab and every open detail of the knowledge page, and the overview's counts",
    async (mutation) => {
      const client = new QueryClient();
      client.setQueryData(adminKeys.knowledgeDrafts("pending"), []);
      client.setQueryData(adminKeys.knowledgeEntries("active"), []);
      client.setQueryData(adminKeys.knowledgeDraft("d-1"), {});
      client.setQueryData(adminKeys.knowledgeEntry("e-1"), {});
      client.setQueryData(adminKeys.overview("24h"), {});
      client.setQueryData(adminKeys.labels, {});
      await invalidateAfter(client, mutation);
      for (const key of [
        adminKeys.knowledgeDrafts("pending"),
        adminKeys.knowledgeEntries("active"),
        adminKeys.knowledgeDraft("d-1"),
        adminKeys.knowledgeEntry("e-1"),
        adminKeys.overview("24h"),
      ]) {
        expect(client.getQueryState(key)?.isInvalidated, JSON.stringify(key)).toBe(true);
      }
      expect(client.getQueryState(adminKeys.labels)?.isInvalidated).toBe(false);
    },
  );

  it("reaches the overview of every range with one prefix", async () => {
    const client = new QueryClient();
    client.setQueryData(adminKeys.overview("24h"), {});
    client.setQueryData(adminKeys.overview("30d"), {});
    await invalidateAfter(client, "retryJob");
    expect(client.getQueryState(adminKeys.overview("24h"))?.isInvalidated).toBe(true);
    expect(client.getQueryState(adminKeys.overview("30d"))?.isInvalidated).toBe(true);
  });
});
