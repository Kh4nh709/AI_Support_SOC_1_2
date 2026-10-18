// src/api/admin.test.ts — the admin client (P11-T10): one typed function per admin route, each sending
// the method, the path and the JSON body the real handler reads (backend/app/web/routers/admin_*.py,
// labels.py, web/main.py), and the reader of the server's `detail`.
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { ApiError, setTokenSource } from "./client";
import {
  ADMIN_LIMITS,
  ADMIN_REASONS,
  adminErrorOf,
  conflictRow,
  createRule,
  createUser,
  getAudit,
  getDigest,
  getLabelsNext,
  getLlmUsage,
  getOverview,
  listRules,
  listUsers,
  parseAdminDetail,
  postLabel,
  putLlmLimits,
  reloadInventory,
  resetPassword,
  retryJob,
  reviewDigest,
  simulateRule,
  toggleRule,
  undoLabel,
  unlockUser,
  updateUser,
  type AdminError,
} from "./admin";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  setTokenSource(
    () => null,
    () => {},
  );
});
afterAll(() => server.close());

type Seen = {
  method: string;
  path: string;
  search: string;
  raw: string;
  body: unknown;
  contentType: string | null;
  authorization: string | null;
};

/** Answers every /api call with `answer` (a 204 has no body) and records what each call carried. */
function record(answer: JsonBodyType = {}, status = 200): Seen[] {
  const seen: Seen[] = [];
  server.use(
    http.all("/api/*", async ({ request }) => {
      const url = new URL(request.url);
      const raw = await request.text();
      seen.push({
        method: request.method,
        path: url.pathname,
        search: url.search,
        raw,
        body: raw === "" ? undefined : (JSON.parse(raw) as unknown),
        contentType: request.headers.get("content-type"),
        authorization: request.headers.get("authorization"),
      });
      return status === 204
        ? new HttpResponse(null, { status })
        : HttpResponse.json(answer, { status });
    }),
  );
  return seen;
}

const UID = "5f1c0a2e-3b4d-4e5f-8a9b-0123456789ab";
const RULE_ID = "7c1d2e3f-4a5b-4c6d-8e9f-abcdef012345";

type Call = {
  name: string;
  run: () => Promise<unknown>;
  method: string;
  path: string;
  search?: string;
  body?: unknown;
  status?: number;
};

const CALLS: Call[] = [
  {
    name: "getOverview",
    run: () => getOverview("7d"),
    method: "GET",
    path: "/api/admin/overview",
    search: "?range=7d",
  },
  {
    name: "retryJob",
    run: () => retryJob(100412),
    method: "POST",
    path: "/api/admin/jobs/100412/retry",
    body: {},
  },
  {
    name: "reloadInventory",
    run: () => reloadInventory(),
    method: "POST",
    path: "/api/admin/reload-inventory",
    body: {},
  },
  { name: "listUsers", run: () => listUsers(), method: "GET", path: "/api/admin/users" },
  {
    name: "createUser",
    run: () =>
      createUser({
        username: "an.t1",
        display_name: "Nguyễn An",
        role: "tier1",
        password: "một-mật-khẩu-dài",
      }),
    method: "POST",
    path: "/api/admin/users",
    body: {
      username: "an.t1",
      display_name: "Nguyễn An",
      role: "tier1",
      password: "một-mật-khẩu-dài",
    },
  },
  {
    name: "updateUser (role)",
    run: () => updateUser(UID, { role: "tier2" }),
    method: "PATCH",
    path: `/api/admin/users/${UID}`,
    body: { role: "tier2" },
  },
  {
    name: "updateUser (is_active and display_name)",
    run: () => updateUser(UID, { is_active: false, display_name: "Lê Tuấn" }),
    method: "PATCH",
    path: `/api/admin/users/${UID}`,
    body: { is_active: false, display_name: "Lê Tuấn" },
  },
  {
    name: "resetPassword",
    run: () => resetPassword(UID, "mật-khẩu-tạm-12345"),
    method: "POST",
    path: `/api/admin/users/${UID}/password`,
    body: { password: "mật-khẩu-tạm-12345" },
    status: 204,
  },
  {
    name: "unlockUser",
    run: () => unlockUser(UID),
    method: "POST",
    path: `/api/admin/users/${UID}/unlock`,
    body: {},
    status: 204,
  },
  {
    name: "getLlmUsage",
    run: () => getLlmUsage("month"),
    method: "GET",
    path: "/api/admin/llm/usage",
    search: "?range=month",
  },
  {
    name: "putLlmLimits",
    run: () => putLlmLimits({ cap_usd: 40, timeout_s: 90 }),
    method: "PUT",
    path: "/api/admin/llm/limits",
    body: { cap_usd: 40, timeout_s: 90 },
  },
  { name: "listRules", run: () => listRules(), method: "GET", path: "/api/admin/rules" },
  {
    name: "simulateRule",
    run: () => simulateRule([{ field: "category", op: "eq", value: "ssh_failed" }]),
    method: "POST",
    path: "/api/admin/rules/simulate",
    body: { match: [{ field: "category", op: "eq", value: "ssh_failed" }] },
  },
  {
    name: "createRule",
    run: () =>
      createRule({
        name: "Cảnh báo đĩa lab",
        reason: "máy lab",
        match: [{ field: "agent_name", op: "prefix", value: "lab-" }],
      }),
    method: "POST",
    path: "/api/admin/rules",
    body: {
      name: "Cảnh báo đĩa lab",
      reason: "máy lab",
      match: [{ field: "agent_name", op: "prefix", value: "lab-" }],
    },
  },
  {
    name: "toggleRule",
    run: () => toggleRule(RULE_ID, false),
    method: "PATCH",
    path: "/api/admin/rules",
    body: { rule_id: RULE_ID, enabled: false },
  },
  { name: "getDigest (today)", run: () => getDigest(), method: "GET", path: "/api/admin/digest" },
  {
    name: "getDigest (a day)",
    run: () => getDigest("2026-09-30"),
    method: "GET",
    path: "/api/admin/digest",
    search: "?day=2026-09-30",
  },
  {
    name: "reviewDigest",
    run: () => reviewDigest("1661877", "2026-09-30", "wrong"),
    method: "POST",
    path: "/api/admin/digest/1661877/review",
    body: { day: "2026-09-30", verdict: "wrong" },
  },
  {
    name: "getLabelsNext",
    run: () => getLabelsNext(UID),
    method: "GET",
    path: "/api/admin/labels/next",
    search: `?labeler=${UID}`,
  },
  {
    name: "postLabel",
    run: () =>
      postLabel({
        labeler: UID,
        cluster_id: "C-0007",
        label: "benign",
        confidence: 2,
        note: "đã xem log",
      }),
    method: "POST",
    path: "/api/admin/labels",
    body: {
      labeler: UID,
      cluster_id: "C-0007",
      label: "benign",
      confidence: 2,
      note: "đã xem log",
    },
  },
  {
    name: "undoLabel",
    run: () => undoLabel(),
    method: "POST",
    path: "/api/admin/labels/undo",
    body: {},
  },
  {
    name: "getAudit (range only)",
    run: () => getAudit({ range: "7d" }),
    method: "GET",
    path: "/api/admin/audit",
    search: "?range=7d",
  },
];

describe("each admin function sends the method, path and body of its route", () => {
  it.each(CALLS)("$name", async (call) => {
    const seen = record({}, call.status ?? 200);
    await call.run();
    expect(seen).toHaveLength(1);
    const [one] = seen;
    expect(one?.method).toBe(call.method);
    expect(one?.path).toBe(call.path);
    expect(one?.search).toBe(call.search ?? "");
    expect(one?.body).toEqual(call.body);
  });

  it("sends the Bearer token of the session, as every call of the app does", async () => {
    setTokenSource(
      () => "tok-admin",
      () => {},
    );
    const seen = record({ users: [] });
    await listUsers();
    expect(seen[0]?.authorization).toBe("Bearer tok-admin");
  });

  it("returns what the route answered, untouched", async () => {
    const answer = { users: [{ user_id: UID, username: "an.t1" }] };
    record(answer);
    await expect(listUsers()).resolves.toEqual(answer);
  });

  it.each(CALLS.filter((c) => c.status === 204))(
    "$name resolves to nothing on a 204",
    async (c) => {
      record({}, 204);
      await expect(c.run()).resolves.toBeUndefined();
    },
  );
});

describe("every admin write sends a JSON body", () => {
  const writes = CALLS.filter((c) => c.method !== "GET");

  it("covers every write function of the client", () => {
    expect(writes.map((c) => c.method + " " + c.path.replace(UID, ":id"))).toEqual([
      "POST /api/admin/jobs/100412/retry",
      "POST /api/admin/reload-inventory",
      "POST /api/admin/users",
      "PATCH /api/admin/users/:id",
      "PATCH /api/admin/users/:id",
      "POST /api/admin/users/:id/password",
      "POST /api/admin/users/:id/unlock",
      "PUT /api/admin/llm/limits",
      "POST /api/admin/rules/simulate",
      "POST /api/admin/rules",
      "PATCH /api/admin/rules",
      "POST /api/admin/digest/1661877/review",
      "POST /api/admin/labels",
      "POST /api/admin/labels/undo",
    ]);
  });

  it.each(writes)("$name carries Content-Type: application/json and an object", async (call) => {
    const seen = record({}, call.status ?? 200);
    await call.run();
    expect(seen[0]?.contentType).toMatch(/^application\/json/);
    expect(typeof seen[0]?.body).toBe("object");
    expect(seen[0]?.body).not.toBeNull();
  });

  it.each(CALLS.filter((c) => c.method === "GET"))(
    "$name sends no body and no Content-Type",
    async (c) => {
      const seen = record({});
      await c.run();
      expect(seen[0]?.raw).toBe("");
      expect(seen[0]?.contentType).toBeNull();
    },
  );

  // The route reads the body by hand and refuses a POST without it: a bare POST is a 422 `invalid` on
  // `body` (P11-T02 review, m3), so the client must send `{}`, and the wire text is exactly that.
  it("unlockUser sends Content-Type: application/json with the body {}", async () => {
    const seen = record({}, 204);
    await unlockUser(UID);
    expect(seen[0]?.contentType).toBe("application/json");
    expect(seen[0]?.raw).toBe("{}");
  });

  it("undoLabel and retryJob send {} the same way", async () => {
    const seen = record({});
    await undoLabel();
    await retryJob(7);
    expect(seen.map((s) => [s.contentType, s.raw])).toEqual([
      ["application/json", "{}"],
      ["application/json", "{}"],
    ]);
  });
});

describe("the ids in a path are encoded", () => {
  it("encodes an alert id that holds a slash or a percent sign", async () => {
    const seen = record({});
    await reviewDigest("a/b%c", "2026-09-30", "unsure");
    expect(seen[0]?.path).toBe("/api/admin/digest/a%2Fb%25c/review");
  });

  it("encodes a user id and a labeler", async () => {
    const seen = record({});
    await updateUser("x/y", { role: "tier1" });
    await getLabelsNext("a&b=c");
    expect(seen[0]?.path).toBe("/api/admin/users/x%2Fy");
    expect(seen[1]?.search).toBe("?labeler=a%26b%3Dc");
  });
});

describe("getAudit sends only the filters that are set", () => {
  const params = (search: string) => Object.fromEntries(new URLSearchParams(search));

  it("sends every filter, the cursor and the limit", async () => {
    const seen = record({ events: [], next_cursor: null, total: 0 });
    await getAudit({
      range: "30d",
      group: "configuration",
      actor: "hoa.admin",
      subject: "job 1/2",
      cursor: 880,
      limit: 20,
    });
    expect(params(seen[0]?.search ?? "")).toEqual({
      range: "30d",
      group: "configuration",
      actor: "hoa.admin",
      subject: "job 1/2",
      cursor: "880",
      limit: "20",
    });
  });

  it("leaves out an unset filter and an empty one: the server answers 422 to an empty text", async () => {
    const seen = record({ events: [], next_cursor: null, total: null });
    await getAudit({ range: "24h", group: undefined, actor: "", subject: "", cursor: undefined });
    expect(params(seen[0]?.search ?? "")).toEqual({ range: "24h" });
  });
});

describe("ADMIN_LIMITS", () => {
  it("mirrors what the create and reset routes check", () => {
    expect(ADMIN_LIMITS.passwordMin).toBe(12);
    expect(ADMIN_LIMITS.passwordMax).toBe(256);
    expect(ADMIN_LIMITS.displayNameMax).toBe(100);
    expect(ADMIN_LIMITS.noteMax).toBe(200);
    expect(ADMIN_LIMITS.username.test("an.t1")).toBe(true);
    expect(ADMIN_LIMITS.username.test("An")).toBe(false);
    expect(ADMIN_LIMITS.username.test("a b")).toBe(false);
    expect(ADMIN_LIMITS.username.test("ab")).toBe(false);
    expect(ADMIN_LIMITS.username.test("x".repeat(33))).toBe(false);
    // `$` would admit a trailing newline; the server uses fullmatch.
    expect(ADMIN_LIMITS.username.test("abc\n")).toBe(false);
  });
});

describe("parseAdminDetail", () => {
  it.each(ADMIN_REASONS)("reads {reason: %s} as a reason", (reason) => {
    expect(parseAdminDetail({ reason })).toEqual({ kind: "reason", reason, extra: {} });
  });

  it("keeps the rest of the object as `extra`", () => {
    const row = { alert_id: "1661877" };
    expect(parseAdminDetail({ reason: "already_reviewed", row })).toEqual({
      kind: "reason",
      reason: "already_reviewed",
      extra: { row },
    });
  });

  it("reads {field, reason} as a field error", () => {
    expect(parseAdminDetail({ field: "username", reason: "invalid" })).toEqual({
      kind: "field",
      field: "username",
      reason: "invalid",
    });
    expect(parseAdminDetail({ field: "verdict", reason: "invalid" })).toEqual({
      kind: "field",
      field: "verdict",
      reason: "invalid",
    });
    expect(parseAdminDetail({ field: "body", reason: "invalid" })).toEqual({
      kind: "field",
      field: "body",
      reason: "invalid",
    });
  });

  it("carries min and max when the server sends numbers", () => {
    expect(parseAdminDetail({ field: "password", reason: "too_short", min: 12 })).toEqual({
      kind: "field",
      field: "password",
      reason: "too_short",
      min: 12,
    });
    expect(parseAdminDetail({ field: "display_name", reason: "too_long", max: 100 })).toEqual({
      kind: "field",
      field: "display_name",
      reason: "too_long",
      max: 100,
    });
    expect(
      parseAdminDetail({ field: "timeout_s", reason: "out_of_range", min: 10, max: 120 }),
    ).toEqual({ kind: "field", field: "timeout_s", reason: "out_of_range", min: 10, max: 120 });
  });

  it("ignores a min or max that is not a finite number", () => {
    expect(
      parseAdminDetail({ field: "cap_usd", reason: "out_of_range", min: "1", max: null }),
    ).toEqual({ kind: "field", field: "cap_usd", reason: "out_of_range" });
    expect(
      parseAdminDetail({
        field: "cap_usd",
        reason: "out_of_range",
        min: Number.NaN,
        max: Infinity,
      }),
    ).toEqual({ kind: "field", field: "cap_usd", reason: "out_of_range" });
  });

  it("reads the plain-text details of the legacy routes as the reason they stand for", () => {
    expect(parseAdminDetail("forbidden")).toEqual({
      kind: "reason",
      reason: "forbidden",
      extra: {},
    });
    expect(parseAdminDetail("rule not found")).toEqual({
      kind: "reason",
      reason: "rule_not_found",
      extra: {},
    });
    expect(parseAdminDetail("cluster is not a gold candidate")).toEqual({
      kind: "reason",
      reason: "unknown_cluster",
      extra: {},
    });
    expect(parseAdminDetail("already labelled by this labeler")).toEqual({
      kind: "reason",
      reason: "already_labelled",
      extra: {},
    });
    expect(parseAdminDetail("the gold set is frozen")).toEqual({
      kind: "reason",
      reason: "frozen",
      extra: {},
    });
    expect(parseAdminDetail("labeler must be the current user")).toEqual({
      kind: "reason",
      reason: "labeler_mismatch",
      extra: {},
    });
  });

  it("reads any other text as a message, shown as the server wrote it", () => {
    expect(parseAdminDetail("simulate: match is outside the whitelist or malformed: []")).toEqual({
      kind: "message",
      message: "simulate: match is outside the whitelist or malformed: []",
    });
  });

  it("reads a list of texts (the 422 of the inventory reload) as messages", () => {
    expect(parseAdminDetail(["inventory.yaml:14: bad criticality", "iocs.csv:3: bad row"])).toEqual(
      {
        kind: "messages",
        messages: ["inventory.yaml:14: bad criticality", "iocs.csv:3: bad row"],
      },
    );
  });

  it("reads FastAPI's own list-shaped 422 as other", () => {
    const fastapi = [
      { type: "missing", loc: ["body", "name"], msg: "Field required", input: { reason: "x" } },
      { type: "bool_parsing", loc: ["body", "enabled"], msg: "bad", input: "maybe" },
    ];
    expect(parseAdminDetail(fastapi)).toEqual({ kind: "other" });
  });

  it.each<[string, unknown]>([
    ["an empty list", []],
    ["a list that mixes texts and objects", ["text", { type: "x" }]],
    ["null", null],
    ["undefined", undefined],
    ["a number", 422],
    ["true", true],
    ["an empty text", ""],
    ["an object with no reason", { detail: "x" }],
    ["an object with a reason that is not a text", { reason: 5 }],
    ["a reason this client does not know", { reason: "brand_new_code" }],
    ["a field with a reason this client does not know", { field: "x", reason: "nope" }],
    ["a field that is not a text", { field: 3, reason: "invalid" }],
  ])("reads %s as other", (_name, detail) => {
    expect(parseAdminDetail(detail)).toEqual({ kind: "other" });
  });

  it.each(["__proto__", "constructor", "toString", "hasOwnProperty", "length"])(
    "does not take the name %s for a reason",
    (name) => {
      expect(parseAdminDetail({ reason: name })).toEqual({ kind: "other" });
      expect(parseAdminDetail({ field: "x", reason: name })).toEqual({ kind: "other" });
      expect(parseAdminDetail(name)).toEqual({ kind: "message", message: name });
    },
  );

  it("lists each reason once", () => {
    expect(new Set(ADMIN_REASONS).size).toBe(ADMIN_REASONS.length);
  });
});

describe("adminErrorOf", () => {
  it("reads the detail of an ApiError", () => {
    expect(adminErrorOf(new ApiError(409, { reason: "self_change" }))).toEqual({
      kind: "reason",
      reason: "self_change",
      extra: {},
    });
  });

  it("reads anything that is not an ApiError as other", () => {
    expect(adminErrorOf(new TypeError("Failed to fetch"))).toEqual({ kind: "other" });
    expect(adminErrorOf("boom")).toEqual({ kind: "other" });
    expect(adminErrorOf(null)).toEqual({ kind: "other" });
  });

  it("reads a 401, which has no detail, as other", () => {
    expect(adminErrorOf(new ApiError(401, null))).toEqual({ kind: "other" });
  });

  it("reads a reason off a real 409 of the client", async () => {
    server.use(
      http.patch(`/api/admin/users/${UID}`, () =>
        HttpResponse.json({ detail: { reason: "last_active_admin" } }, { status: 409 }),
      ),
    );
    const error = await updateUser(UID, { role: "tier1" }).catch((e: unknown) => e);
    expect(adminErrorOf(error)).toEqual({ kind: "reason", reason: "last_active_admin", extra: {} });
  });

  it("reads a field error off a real 422 of the client", async () => {
    server.use(
      http.put("/api/admin/llm/limits", () =>
        HttpResponse.json(
          { detail: { field: "timeout_s", reason: "out_of_range", min: 10, max: 120 } },
          { status: 422 },
        ),
      ),
    );
    const error = await putLlmLimits({ timeout_s: 600 }).catch((e: unknown) => e);
    expect(adminErrorOf(error)).toEqual({
      kind: "field",
      field: "timeout_s",
      reason: "out_of_range",
      min: 10,
      max: 120,
    });
  });

  it("reads FastAPI's list-shaped 422 off a real answer as other", async () => {
    server.use(
      http.post("/api/admin/rules", () =>
        HttpResponse.json(
          { detail: [{ type: "missing", loc: ["body", "name"], msg: "Field required" }] },
          { status: 422 },
        ),
      ),
    );
    const error = await createRule({ name: "", reason: "", match: [] }).catch((e: unknown) => e);
    expect(adminErrorOf(error)).toEqual({ kind: "other" });
  });

  it("reads the file errors off the real 422 of the inventory reload", async () => {
    server.use(
      http.post("/api/admin/reload-inventory", () =>
        HttpResponse.json(
          { detail: ["inventory.yaml:14: bad", "iocs.csv:2: bad"] },
          { status: 422 },
        ),
      ),
    );
    const error = await reloadInventory().catch((e: unknown) => e);
    expect(adminErrorOf(error)).toEqual({
      kind: "messages",
      messages: ["inventory.yaml:14: bad", "iocs.csv:2: bad"],
    });
  });
});

describe("conflictRow", () => {
  const row = {
    alert_id: "1661877",
    rule_id: "5710",
    description: "x",
    severity: "low",
    category: "ssh",
    agent_name: "lab-01",
    occurrence_count: 3,
    first_seen_at: "2026-09-30T01:00:00+00:00",
    last_seen_at: "2026-09-30T02:00:00+00:00",
    autoclose_rule_id: null,
    autoclose_rule_name: null,
    suggested_action: null,
    disagreement: false,
    reviewed_verdict: "correct",
    reviewed_by_name: "nguyen-admin",
    reviewed_at: "2026-09-30T01:12:00+00:00",
    reopened_by_review: false,
  };

  it("returns the row an already_reviewed 409 carries", () => {
    const error = parseAdminDetail({ reason: "already_reviewed", row });
    expect(conflictRow(error)?.alert_id).toBe("1661877");
    expect(conflictRow(error)?.reviewed_verdict).toBe("correct");
  });

  it("returns null for any other error, or a row that is not a row", () => {
    const none: AdminError[] = [
      parseAdminDetail({ reason: "not_auto_closed" }),
      parseAdminDetail({ reason: "already_reviewed" }),
      parseAdminDetail({ reason: "already_reviewed", row: "text" }),
      parseAdminDetail({ reason: "already_reviewed", row: { alert_id: 5 } }),
      parseAdminDetail({ field: "verdict", reason: "invalid" }),
      { kind: "other" },
    ];
    for (const error of none) expect(conflictRow(error)).toBeNull();
  });
});
