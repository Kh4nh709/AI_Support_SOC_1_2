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

  it("starts every key with admin, so one prefix reaches the whole console", () => {
    const all = [
      adminKeys.overview("24h"),
      adminKeys.users,
      adminKeys.llmUsage("7d"),
      adminKeys.rules,
      adminKeys.digest(null),
      adminKeys.labels,
      adminKeys.audit({ range: "24h" }),
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
        "createRule",
        "createUser",
        "postLabel",
        "putLlmLimits",
        "reloadInventory",
        "resetPassword",
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
    ["createRule", [adminKeys.rules, adminKeys.auditAll]],
    ["toggleRule", [adminKeys.rules, adminKeys.auditAll]],
    ["reviewDigest", [adminKeys.digestAll, adminKeys.overviewAll, adminKeys.auditAll]],
    ["postLabel", [adminKeys.labels, adminKeys.auditAll]],
    ["undoLabel", [adminKeys.labels, adminKeys.auditAll]],
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

  it("reaches the overview of every range with one prefix", async () => {
    const client = new QueryClient();
    client.setQueryData(adminKeys.overview("24h"), {});
    client.setQueryData(adminKeys.overview("30d"), {});
    await invalidateAfter(client, "retryJob");
    expect(client.getQueryState(adminKeys.overview("24h"))?.isInvalidated).toBe(true);
    expect(client.getQueryState(adminKeys.overview("30d"))?.isInvalidated).toBe(true);
  });
});
