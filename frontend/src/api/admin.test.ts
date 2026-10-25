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
  approveKnowledgeDraft,
  conflictRow,
  createRule,
  createUser,
  getAudit,
  getDigest,
  getKnowledgeDraft,
  getKnowledgeEntry,
  getKnowledgeTags,
  getLabelsNext,
  getLlmUsage,
  getOverview,
  knowledgeErrorOf,
  listKnowledgeDrafts,
  listKnowledgeEntries,
  listRules,
  listUsers,
  parseAdminDetail,
  postLabel,
  putLlmLimits,
  rejectKnowledgeDraft,
  reloadInventory,
  resetPassword,
  retireKnowledgeEntry,
  retryJob,
  reviewDigest,
  simulateRule,
  toggleRule,
  undoLabel,
  unlockUser,
  updateUser,
  type AdminError,
  type AdminReason,
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
const DRAFT_ID = "0b7e4f10-2c3d-4a5b-9c8d-111111111111";
const ENTRY_ID = "3a9d5e20-4b6c-4d7e-8f90-222222222222";

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
  // --- learned knowledge (admin_knowledge.py, P13-T05): the reads send no body, the writes send a JSON object ---
  {
    name: "listKnowledgeDrafts",
    run: () => listKnowledgeDrafts("pending"),
    method: "GET",
    path: "/api/admin/knowledge/drafts",
    search: "?status=pending",
  },
  {
    name: "getKnowledgeDraft",
    run: () => getKnowledgeDraft(DRAFT_ID),
    method: "GET",
    path: `/api/admin/knowledge/drafts/${DRAFT_ID}`,
  },
  {
    name: "approveKnowledgeDraft (as it is)",
    run: () => approveKnowledgeDraft(DRAFT_ID),
    method: "POST",
    path: `/api/admin/knowledge/drafts/${DRAFT_ID}/approve`,
    body: {},
  },
  {
    name: "approveKnowledgeDraft (edited)",
    run: () => approveKnowledgeDraft(DRAFT_ID, { title: "Tiêu đề mới", tags: ["port_scan"] }),
    method: "POST",
    path: `/api/admin/knowledge/drafts/${DRAFT_ID}/approve`,
    body: { edited: { title: "Tiêu đề mới", tags: ["port_scan"] } },
  },
  {
    name: "rejectKnowledgeDraft",
    run: () => rejectKnowledgeDraft(DRAFT_ID, "trùng với mục khác"),
    method: "POST",
    path: `/api/admin/knowledge/drafts/${DRAFT_ID}/reject`,
    body: { reason: "trùng với mục khác" },
  },
  {
    name: "listKnowledgeEntries",
    run: () => listKnowledgeEntries("retired"),
    method: "GET",
    path: "/api/admin/knowledge/entries",
    search: "?status=retired",
  },
  {
    name: "getKnowledgeEntry",
    run: () => getKnowledgeEntry(ENTRY_ID),
    method: "GET",
    path: `/api/admin/knowledge/entries/${ENTRY_ID}`,
  },
  {
    name: "retireKnowledgeEntry",
    run: () => retireKnowledgeEntry(ENTRY_ID, "không còn đúng"),
    method: "POST",
    path: `/api/admin/knowledge/entries/${ENTRY_ID}/retire`,
    body: { reason: "không còn đúng" },
  },
  {
    name: "getKnowledgeTags",
    run: () => getKnowledgeTags(),
    method: "GET",
    path: "/api/admin/knowledge/tags",
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
      `POST /api/admin/knowledge/drafts/${DRAFT_ID}/approve`,
      `POST /api/admin/knowledge/drafts/${DRAFT_ID}/approve`,
      `POST /api/admin/knowledge/drafts/${DRAFT_ID}/reject`,
      `POST /api/admin/knowledge/entries/${ENTRY_ID}/retire`,
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

  // The two actor names of an audit row that is not a person (`system`, `llm`): the create route refuses
  // them as usernames (P11-T20), because the audit page's actor filter reads them as roles, not as users.
  it("lists the usernames the create form must refuse before it posts", () => {
    expect([...ADMIN_LIMITS.reservedUsernames]).toEqual(["system", "llm"]);
    for (const name of ADMIN_LIMITS.reservedUsernames) {
      // They fit the username pattern: only the list keeps them out.
      expect(ADMIN_LIMITS.username.test(name)).toBe(true);
    }
  });
});

/** A `detail` as the server answered it, at a status (a conflict unless a test says another). */
const parse = (detail: unknown, status = 409): AdminError => parseAdminDetail(detail, status);

describe("parseAdminDetail", () => {
  it.each(ADMIN_REASONS)("reads {reason: %s} as a reason", (reason) => {
    expect(parse({ reason })).toEqual({ kind: "reason", status: 409, reason, extra: {} });
  });

  it("carries the status of the answer in every kind", () => {
    expect(parse({ reason: "not_found" }, 404).status).toBe(404);
    expect(parse({ field: "username", reason: "invalid" }, 422).status).toBe(422);
    expect(parse("a text", 422).status).toBe(422);
    expect(parse(["a text"], 422).status).toBe(422);
    expect(parse(null, 500).status).toBe(500);
  });

  it("keeps the rest of the object as `extra`", () => {
    const row = { alert_id: "1661877" };
    expect(parse({ reason: "already_reviewed", row })).toEqual({
      kind: "reason",
      status: 409,
      reason: "already_reviewed",
      extra: { row },
    });
  });

  it("reads {field, reason} as a field error", () => {
    expect(parse({ field: "username", reason: "invalid" }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "username",
      reason: "invalid",
    });
    expect(parse({ field: "verdict", reason: "invalid" }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "verdict",
      reason: "invalid",
    });
    expect(parse({ field: "body", reason: "invalid" }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "body",
      reason: "invalid",
    });
  });

  it("reads the username a create refuses as reserved", () => {
    expect(parse({ field: "username", reason: "reserved" }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "username",
      reason: "reserved",
    });
  });

  it("carries min and max when the server sends numbers", () => {
    expect(parse({ field: "password", reason: "too_short", min: 12 }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "password",
      reason: "too_short",
      min: 12,
    });
    expect(parse({ field: "display_name", reason: "too_long", max: 100 }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "display_name",
      reason: "too_long",
      max: 100,
    });
    expect(parse({ field: "timeout_s", reason: "out_of_range", min: 10, max: 120 }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "timeout_s",
      reason: "out_of_range",
      min: 10,
      max: 120,
    });
  });

  it("ignores a min or max that is not a finite number", () => {
    expect(parse({ field: "cap_usd", reason: "out_of_range", min: "1", max: null }, 422)).toEqual({
      kind: "field",
      status: 422,
      field: "cap_usd",
      reason: "out_of_range",
    });
    expect(
      parse({ field: "cap_usd", reason: "out_of_range", min: Number.NaN, max: Infinity }, 422),
    ).toEqual({ kind: "field", status: 422, field: "cap_usd", reason: "out_of_range" });
  });

  it.each<[text: string, status: number, reason: AdminReason]>([
    ["forbidden", 403, "forbidden"],
    ["rule not found", 404, "rule_not_found"],
    ["cluster is not a gold candidate", 404, "unknown_cluster"],
    ["already labelled by this labeler", 409, "already_labelled"],
    ["the gold set is frozen", 409, "frozen"],
    ["labeler must be the current user", 403, "labeler_mismatch"],
    // `deps.clean_path_id`: a control character in an alert id on the digest review path.
    ["not found", 404, "not_found"],
  ])(
    "reads the plain text %j of the older routes as the reason it stands for",
    (text, status, reason) => {
      expect(parse(text, status)).toEqual({ kind: "reason", status, reason, extra: {} });
    },
  );

  describe("a text is a message only on a 422", () => {
    const TEXT = "simulate: match is outside the whitelist or malformed: []";

    it("reads the 422 of a rule, which says what is wrong with it, as a message", () => {
      expect(parse(TEXT, 422)).toEqual({ kind: "message", status: 422, message: TEXT });
    });

    it.each([400, 401, 403, 404, 405, 409, 500, 502, 503])(
      "reads the same text at %i as other, not as English shown to the admin",
      (status) => {
        expect(parse(TEXT, status)).toEqual({ kind: "other", status });
      },
    );

    it.each<[text: string, status: number]>([
      ["Not Found", 404], // FastAPI's own, for a path that is not a route
      ["Method Not Allowed", 405],
      ["auth disabled: JWT_SECRET unset", 503], // `deps.current_user`
      ["Internal Server Error", 500],
    ])("reads %j (%i) as other", (text, status) => {
      expect(parse(text, status)).toEqual({ kind: "other", status });
    });

    it("reads a list of texts (the 422 of the inventory reload) as messages", () => {
      expect(parse(["inventory.yaml:14: bad criticality", "iocs.csv:3: bad row"], 422)).toEqual({
        kind: "messages",
        status: 422,
        messages: ["inventory.yaml:14: bad criticality", "iocs.csv:3: bad row"],
      });
    });

    it("reads a list of texts at any other status as other", () => {
      expect(parse(["inventory.yaml:14: bad"], 500)).toEqual({ kind: "other", status: 500 });
      expect(parse(["inventory.yaml:14: bad"], 409)).toEqual({ kind: "other", status: 409 });
    });
  });

  it("reads FastAPI's own list-shaped 422 as other", () => {
    const fastapi = [
      { type: "missing", loc: ["body", "name"], msg: "Field required", input: { reason: "x" } },
      { type: "bool_parsing", loc: ["body", "enabled"], msg: "bad", input: "maybe" },
    ];
    expect(parse(fastapi, 422)).toEqual({ kind: "other", status: 422 });
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
    expect(parse(detail, 422)).toEqual({ kind: "other", status: 422 });
  });

  it.each(["__proto__", "constructor", "toString", "hasOwnProperty", "length"])(
    "does not take the name %s for a reason",
    (name) => {
      expect(parse({ reason: name }, 422)).toEqual({ kind: "other", status: 422 });
      expect(parse({ field: "x", reason: name }, 422)).toEqual({ kind: "other", status: 422 });
      // As a plain text it is not one of the older routes' texts: a message at 422, other elsewhere.
      expect(parse(name, 422)).toEqual({ kind: "message", status: 422, message: name });
      expect(parse(name, 404)).toEqual({ kind: "other", status: 404 });
    },
  );

  it("lists each reason once", () => {
    expect(new Set(ADMIN_REASONS).size).toBe(ADMIN_REASONS.length);
  });

  it("lists the reserved username reason, which P11-T20 adds to the create route", () => {
    expect(ADMIN_REASONS).toContain("reserved");
  });
});

describe("adminErrorOf", () => {
  it("reads the detail and the status of an ApiError", () => {
    expect(adminErrorOf(new ApiError(409, { reason: "self_change" }))).toEqual({
      kind: "reason",
      status: 409,
      reason: "self_change",
      extra: {},
    });
  });

  it("reads anything that is not an ApiError as other, with no status (0)", () => {
    expect(adminErrorOf(new TypeError("Failed to fetch"))).toEqual({ kind: "other", status: 0 });
    expect(adminErrorOf("boom")).toEqual({ kind: "other", status: 0 });
    expect(adminErrorOf(null)).toEqual({ kind: "other", status: 0 });
  });

  it("reads a 401, which has no detail, as other", () => {
    expect(adminErrorOf(new ApiError(401, null))).toEqual({ kind: "other", status: 401 });
  });

  it("reads a reason off a real 409 of the client", async () => {
    server.use(
      http.patch(`/api/admin/users/${UID}`, () =>
        HttpResponse.json({ detail: { reason: "last_active_admin" } }, { status: 409 }),
      ),
    );
    const error = await updateUser(UID, { role: "tier1" }).catch((e: unknown) => e);
    expect(adminErrorOf(error)).toEqual({
      kind: "reason",
      status: 409,
      reason: "last_active_admin",
      extra: {},
    });
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
      status: 422,
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
    expect(adminErrorOf(error)).toEqual({ kind: "other", status: 422 });
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
      status: 422,
      messages: ["inventory.yaml:14: bad", "iocs.csv:2: bad"],
    });
  });

  it("reads the 422 text of a refused rule as a message", async () => {
    const text = "simulate: match is outside the whitelist or malformed: [{'field': 'x'}]";
    server.use(
      http.post("/api/admin/rules/simulate", () =>
        HttpResponse.json({ detail: text }, { status: 422 }),
      ),
    );
    const error = await simulateRule([]).catch((e: unknown) => e);
    expect(adminErrorOf(error)).toEqual({ kind: "message", status: 422, message: text });
  });

  it("reads the 404 text of a bad alert id on the digest review path as not_found", async () => {
    server.use(
      http.post("/api/admin/digest/:id/review", () =>
        HttpResponse.json({ detail: "not found" }, { status: 404 }),
      ),
    );
    const error = await reviewDigest("x\u0000y", "2026-09-30", "correct").catch((e: unknown) => e);
    expect(adminErrorOf(error)).toEqual({
      kind: "reason",
      status: 404,
      reason: "not_found",
      extra: {},
    });
  });

  it.each<[text: string, status: number]>([
    ["Not Found", 404],
    ["Method Not Allowed", 405],
    ["auth disabled: JWT_SECRET unset", 503],
  ])(
    "reads the English %j of %i off a real answer as other, never as text to show",
    async (text, status) => {
      server.use(
        http.get("/api/admin/users", () => HttpResponse.json({ detail: text }, { status })),
      );
      const error = await listUsers().catch((e: unknown) => e);
      expect(adminErrorOf(error)).toEqual({ kind: "other", status });
    },
  );
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
    const error = parse({ reason: "already_reviewed", row });
    expect(conflictRow(error)?.alert_id).toBe("1661877");
    expect(conflictRow(error)?.reviewed_verdict).toBe("correct");
  });

  it("returns null for any other error, or a row that is not a row", () => {
    const none: AdminError[] = [
      parse({ reason: "not_auto_closed" }),
      parse({ reason: "already_reviewed" }),
      parse({ reason: "already_reviewed", row: "text" }),
      parse({ reason: "already_reviewed", row: { alert_id: 5 } }),
      parse({ field: "verdict", reason: "invalid" }, 422),
      { kind: "other", status: 0 },
    ];
    for (const error of none) expect(conflictRow(error)).toBeNull();
  });
});

// --- learned knowledge (P13-T06; the routes are admin_knowledge.py of P13-T05) -----------------------------------

describe("approveKnowledgeDraft sends the six model fields and nothing else", () => {
  it("sends {} for an approval as it is, and for an edit that changed nothing", async () => {
    const seen = record({ entry_id: ENTRY_ID });
    await approveKnowledgeDraft(DRAFT_ID);
    await approveKnowledgeDraft(DRAFT_ID, {});
    expect(seen.map((s) => [s.contentType, s.raw])).toEqual([
      ["application/json", "{}"],
      ["application/json", "{}"],
    ]);
  });

  it("never sends a closed field: the route refuses one with 422 v1_schema:unexpected_key", async () => {
    const seen = record({ entry_id: ENTRY_ID });
    // The type does not allow a closed key; a value that got past the type system is still not sent.
    const sneaky = {
      title: "Tiêu đề",
      category: "recon",
      conclusion: "closed_benign",
      mitre_ids: ["T1046"],
      soar_scenario: "SC03",
      rule_ids: ["100190"],
      log_source: "wazuh",
      draft_id: "x",
    } as never;
    await approveKnowledgeDraft(DRAFT_ID, sneaky);
    expect(seen[0]?.body).toEqual({ edited: { title: "Tiêu đề" } });
  });

  it("sends each of the six model fields it is given, as they are", async () => {
    const seen = record({ entry_id: ENTRY_ID });
    const all = {
      title: "T",
      summary: "S",
      distinguishing_signals: ["a", "b"],
      check_next_time: ["c"],
      confidence_note: "N",
      tags: ["port_scan"],
    };
    await approveKnowledgeDraft(DRAFT_ID, all);
    expect(seen[0]?.body).toEqual({ edited: all });
  });

  it("encodes the id in the path", async () => {
    const seen = record({ entry_id: ENTRY_ID });
    await approveKnowledgeDraft("a/b%c", {});
    expect(seen[0]?.path).toBe("/api/admin/knowledge/drafts/a%2Fb%25c/approve");
  });
});

describe("the knowledge lists ask for the status they are given", () => {
  it.each(["pending", "approved", "merged", "rejected"] as const)(
    "listKnowledgeDrafts(%s)",
    async (status) => {
      const seen = record([]);
      await listKnowledgeDrafts(status);
      expect(seen[0]?.search).toBe(`?status=${status}`);
    },
  );

  it.each(["active", "retired"] as const)("listKnowledgeEntries(%s)", async (status) => {
    const seen = record([]);
    await listKnowledgeEntries(status);
    expect(seen[0]?.search).toBe(`?status=${status}`);
  });
});

describe("knowledgeErrorOf", () => {
  const fail = (status: number, body: unknown) =>
    new ApiError(status, (body as { detail?: unknown } | null)?.detail ?? body, body);

  it("reads the faults of a 422 as rule and field, in the order the route sent them", () => {
    const error = fail(422, { faults: ["v3_ipv4:summary", "v5_length:title", "v1_schema:root"] });
    expect(knowledgeErrorOf(error)).toEqual({
      kind: "faults",
      status: 422,
      faults: [
        { rule: "v3_ipv4", field: "summary" },
        { rule: "v5_length", field: "title" },
        { rule: "v1_schema", field: "root" },
      ],
    });
  });

  it("splits a fault at the first colon only, and keeps one with no colon as a rule with no field", () => {
    expect(knowledgeErrorOf(fail(422, { faults: ["v9_new:a:b", "weird"] }))).toEqual({
      kind: "faults",
      status: 422,
      faults: [
        { rule: "v9_new", field: "a:b" },
        { rule: "weird", field: null },
      ],
    });
  });

  it("reads the faults off a real 422 of the client", async () => {
    server.use(
      http.post(`/api/admin/knowledge/drafts/${DRAFT_ID}/approve`, () =>
        HttpResponse.json({ faults: ["v1_schema:unexpected_key"] }, { status: 422 }),
      ),
    );
    const error = await approveKnowledgeDraft(DRAFT_ID, { title: "x" }).catch((e: unknown) => e);
    expect(knowledgeErrorOf(error)).toEqual({
      kind: "faults",
      status: 422,
      faults: [{ rule: "v1_schema", field: "unexpected_key" }],
    });
  });

  it.each([
    ["an empty list", { faults: [] }],
    ["a list with a non-text item", { faults: ["v3_ipv4:summary", 7] }],
    ["a faults key that is not a list", { faults: "v3_ipv4:summary" }],
  ])("reads %s as other, not as a fault list", (_name, body) => {
    expect(knowledgeErrorOf(fail(422, body))).toEqual({ kind: "other", status: 422 });
  });

  it("reads the 422 of a reason as a field error on the reason", () => {
    expect(
      knowledgeErrorOf(fail(422, { detail: { field: "reason", reason: "required" } })),
    ).toEqual({ kind: "field", status: 422, field: "reason", reason: "required" });
    expect(knowledgeErrorOf(fail(422, { detail: { field: "edited", reason: "invalid" } }))).toEqual(
      { kind: "field", status: 422, field: "edited", reason: "invalid" },
    );
  });

  it("reads FastAPI's own list-shaped 422 as other", () => {
    expect(
      knowledgeErrorOf(fail(422, { detail: [{ type: "missing", loc: ["body"], msg: "x" }] })),
    ).toEqual({ kind: "other", status: 422 });
  });

  it.each(["not_pending", "source_changed", "unpublishable", "not_active", "anything_new"])(
    "reads a 409 with the reason %s as a stale write, whatever the reason",
    (reason) => {
      expect(knowledgeErrorOf(fail(409, { detail: { reason } }))).toEqual({
        kind: "stale",
        status: 409,
        reason,
      });
    },
  );

  it("reads a 409 with no reason as a stale write too", () => {
    expect(knowledgeErrorOf(fail(409, { detail: "conflict" }))).toEqual({
      kind: "stale",
      status: 409,
      reason: "unknown",
    });
  });

  it("reads the 503 publish_failed as retryable, and any other 503 as other", () => {
    expect(knowledgeErrorOf(fail(503, { detail: { reason: "publish_failed" } }))).toEqual({
      kind: "publish_failed",
      status: 503,
    });
    expect(knowledgeErrorOf(fail(503, { detail: { reason: "timeout" } }))).toEqual({
      kind: "other",
      status: 503,
    });
  });

  it("reads the 404 not_found, and a 404 of FastAPI's own text as other", () => {
    expect(knowledgeErrorOf(fail(404, { detail: { reason: "not_found" } }))).toEqual({
      kind: "not_found",
      status: 404,
    });
    expect(knowledgeErrorOf(fail(404, { detail: "Not Found" }))).toEqual({
      kind: "other",
      status: 404,
    });
  });

  it("reads anything that is not an ApiError as other, with no status (0)", () => {
    expect(knowledgeErrorOf(new TypeError("Failed to fetch"))).toEqual({
      kind: "other",
      status: 0,
    });
    expect(knowledgeErrorOf(null)).toEqual({ kind: "other", status: 0 });
  });

  it("does not answer from the prototype chain", () => {
    expect(knowledgeErrorOf(fail(422, { detail: { field: "constructor" } }))).toEqual({
      kind: "other",
      status: 422,
    });
    const hostile: unknown = JSON.parse('{"detail":{"__proto__":{"reason":"x"}}}');
    expect(knowledgeErrorOf(fail(409, hostile))).toEqual({
      kind: "stale",
      status: 409,
      reason: "unknown",
    });
  });
});
