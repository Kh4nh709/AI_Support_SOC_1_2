// src/features/admin/adminKeys.test.ts — the query keys of the admin pages, and what each write makes stale.
import { QueryClient } from "@tanstack/react-query";
import { ADMIN_MUTATIONS, adminKeys, invalidateAfter, type AdminMutation } from "./adminKeys";

describe("adminKeys", () => {
  it("has the seven keys of the spec", () => {
    expect(adminKeys.overview("24h")).toEqual(["admin", "overview", "24h"]);
    expect(adminKeys.users).toEqual(["admin", "users"]);
    expect(adminKeys.llmUsage("month")).toEqual(["admin", "llm", "usage", "month"]);
    expect(adminKeys.rules).toEqual(["admin", "rules"]);
    expect(adminKeys.digest("2026-09-30")).toEqual(["admin", "digest", "2026-09-30"]);
    expect(adminKeys.labels).toEqual(["admin", "labels"]);
    expect(adminKeys.audit({ range: "7d", group: "users" })).toEqual([
      "admin",
      "audit",
      { range: "7d", group: "users" },
    ]);
  });

  it("keys the digest of today, which has no day in its URL, apart from a named day", () => {
    expect(adminKeys.digest(null)).toEqual(["admin", "digest", null]);
    expect(adminKeys.digest(null)).not.toEqual(adminKeys.digest("2026-09-30"));
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
      adminKeys.rules,
      adminKeys.digest(null),
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
    expect(starts(adminKeys.digest("2026-09-30"), adminKeys.digestAll)).toBe(true);
    expect(starts(adminKeys.digest(null), adminKeys.digestAll)).toBe(true);
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
        "createRule",
        "createUser",
        "postLabel",
        "putLlmLimits",
        "rejectKnowledgeDraft",
        "reloadInventory",
        "resetPassword",
        "retireKnowledgeEntry",
        "retryJob",
        "reviewDigest",
        "toggleRule",
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
    // The digest page shows "no rule enabled" from `rules_enabled` (admin_digest.py), which a rule written or
    // toggled changes.
    ["createRule", [adminKeys.rules, adminKeys.digestAll, adminKeys.auditAll]],
    ["toggleRule", [adminKeys.rules, adminKeys.digestAll, adminKeys.auditAll]],
    ["reviewDigest", [adminKeys.digestAll, adminKeys.overviewAll, adminKeys.auditAll]],
    ["postLabel", [adminKeys.labels, adminKeys.auditAll]],
    ["undoLabel", [adminKeys.labels, adminKeys.auditAll]],
    // The knowledge page's every list and detail (a draft leaves one tab for another, an entry is born or retired),
    // the overview's pending and conflict counts, and the audit page that shows the event.
    ["approveKnowledgeDraft", [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll]],
    ["rejectKnowledgeDraft", [adminKeys.knowledgeAll, adminKeys.overviewAll, adminKeys.auditAll]],
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
    client.setQueryData(adminKeys.rules, []);
    client.setQueryData(adminKeys.audit({ range: "7d" }), { events: [] });
    await invalidateAfter(client, "updateUser");
    expect(client.getQueryState(adminKeys.users)?.isInvalidated).toBe(true);
    expect(client.getQueryState(adminKeys.audit({ range: "7d" }))?.isInvalidated).toBe(true);
    expect(client.getQueryState(adminKeys.rules)?.isInvalidated).toBe(false);
  });

  it.each(["createRule", "toggleRule"] as const)(
    "%s refreshes the digest of every day, whose 'no rule enabled' state a rule changes",
    async (mutation) => {
      const client = new QueryClient();
      client.setQueryData(adminKeys.digest(null), { rules_enabled: false, rows: [] });
      client.setQueryData(adminKeys.digest("2026-09-30"), { rules_enabled: false, rows: [] });
      await invalidateAfter(client, mutation);
      expect(client.getQueryState(adminKeys.digest(null))?.isInvalidated).toBe(true);
      expect(client.getQueryState(adminKeys.digest("2026-09-30"))?.isInvalidated).toBe(true);
    },
  );

  it.each(["approveKnowledgeDraft", "rejectKnowledgeDraft", "retireKnowledgeEntry"] as const)(
    "%s refreshes every tab and every open detail of the knowledge page, and the overview's counts",
    async (mutation) => {
      const client = new QueryClient();
      client.setQueryData(adminKeys.knowledgeDrafts("pending"), []);
      client.setQueryData(adminKeys.knowledgeEntries("active"), []);
      client.setQueryData(adminKeys.knowledgeDraft("d-1"), {});
      client.setQueryData(adminKeys.knowledgeEntry("e-1"), {});
      client.setQueryData(adminKeys.overview("24h"), {});
      client.setQueryData(adminKeys.rules, []);
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
      expect(client.getQueryState(adminKeys.rules)?.isInvalidated).toBe(false);
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
